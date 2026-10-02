"""
Ninja-API-Hunter v4.0
Command-line interface: argument parsing and orchestration. Network
access lives in core.engine; this module just wires things together.
"""
import argparse
import asyncio
import sys
from datetime import datetime

from .core.engine import RequestEngine
from .core.rate_limiter import AdaptiveRateLimiter
from .modules.bola import BOLADetector
from .modules.cors import CORSDetector
from .modules.swagger import SwaggerDiscovery
from .modules.discovery import PassiveDiscovery
from .modules.exposures import ExposureScanner
from .utils import logger, reporter
from .utils.helpers import parse_headers, load_wordlist, classify
from .config import DEFAULT_TIMEOUT, DEFAULT_THREADS, DEFAULT_USER_AGENT, HTTP_METHODS


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ninja-hunter",
        description="Ninja-API-Hunter v4.0 - API reconnaissance and security-assessment toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Baseline discovery + secret/stack-trace grep over a wordlist:
    python3 run.py -t https://api.target.com -w wordlist.txt

  Pull extra paths from robots.txt / sitemap.xml:
    python3 run.py -t https://api.target.com --discover

  Auto-discover and expand a Swagger/OpenAPI spec:
    python3 run.py -t https://api.target.com --swagger

  Probe common exposed-file paths:
    python3 run.py -t https://api.target.com --exposures

  CORS misconfiguration check:
    python3 run.py -t https://api.target.com -w wordlist.txt --cors

  BOLA/IDOR check between two accounts you control:
    python3 run.py -t https://api.target.com -w wordlist.txt \\
      --bola --token-a "$TOKEN_A" --token-b "$TOKEN_B"

  Full assessment with an HTML report, through Burp, ignoring a self-signed cert:
    python3 run.py -t https://api.target.com -w wordlist.txt --all \\
      --proxy http://127.0.0.1:8080 --insecure -o report.html --format html

Use only against systems you own or are explicitly authorized to test.
""",
    )
    parser.add_argument("-t", "--target", required=True, help="Target base URL")
    parser.add_argument("-w", "--wordlist", help="Path to a path/endpoint wordlist")
    parser.add_argument("-m", "--method", default="GET", choices=HTTP_METHODS)
    parser.add_argument("-H", "--headers", action="append", default=[],
                         help='Custom header, repeatable, e.g. -H "Authorization: Bearer X"')

    parser.add_argument("--bola", action="store_true", help="Run the BOLA/IDOR differential test")
    parser.add_argument("--token-a", help="Bearer token for account A (required for --bola)")
    parser.add_argument("--token-b", help="Bearer token for account B (required for --bola)")

    parser.add_argument("--cors", action="store_true", help="Run the CORS misconfiguration test")
    parser.add_argument("--discover", action="store_true",
                         help="Pull extra candidate paths from robots.txt and sitemap.xml")
    parser.add_argument("--swagger", action="store_true", help="Auto-discover and parse Swagger/OpenAPI docs")
    parser.add_argument("--exposures", action="store_true", help="Probe common sensitive-file paths")
    parser.add_argument("--all", action="store_true", help="Run every applicable module")
    parser.add_argument("--no-grep", action="store_true", help="Skip secret/stack-trace pattern grepping")

    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--proxy", default=None, help="Proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)

    parser.add_argument("-o", "--output", default=None, help="Report output file path")
    parser.add_argument("--format", choices=["json", "html"], default="json")

    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    return parser


async def baseline_scan(engine, rate_limiter, urls, method, grep, quiet):
    results = []
    for url in urls:
        resp = await engine.request(method, url, rate_limiter=rate_limiter)
        status = resp.get("status")
        body = resp.get("body") or ""
        entry = {
            "url": url,
            "method": method,
            "status": status,
            "length": len(body),
            "state": classify(status),
        }
        if status is not None:
            entry["missing_headers"] = ExposureScanner.check_security_headers(resp.get("headers"))
        if grep and body:
            entry["secrets"] = ExposureScanner.scan_body_for_secrets(body)
            entry["stack_traces"] = ExposureScanner.scan_body_for_stack_traces(body)

        results.append(entry)

        if not quiet:
            color = {
                "ALIVE": logger.Colors.GREEN, "PROTECTED": logger.Colors.YELLOW,
                "REDIRECT": logger.Colors.BLUE, "DEAD": logger.Colors.RED,
                "ERROR": logger.Colors.RED,
            }[entry["state"]]
            print(f"{color}[{entry['state']:^9}]{logger.Colors.END} {status} {method:6} {url}")
            for s in entry.get("secrets", []):
                logger.critical(f"  -> possible {s['type']} exposed")
    return results


async def run(args):
    if not args.quiet:
        print(logger.banner())

    extra_headers = parse_headers(args.headers)
    target = args.target.rstrip("/")
    run_all = args.all
    findings = {}

    engine = RequestEngine(
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        proxy=args.proxy,
        user_agent=args.user_agent,
        extra_headers=extra_headers,
        threads=args.threads,
    )
    rate_limiter = AdaptiveRateLimiter()

    async with engine:
        urls = []
        if args.wordlist:
            try:
                paths = load_wordlist(args.wordlist)
            except FileNotFoundError:
                logger.error(f"Wordlist not found: {args.wordlist}")
                sys.exit(1)
            urls = [f"{target}/{p.lstrip('/')}" for p in paths]

        if args.discover or run_all:
            logger.info("Checking robots.txt and sitemap.xml...")
            passive = PassiveDiscovery(engine, rate_limiter)
            extra = await passive.discover_all(target)
            if extra:
                logger.success(f"Found {len(extra)} additional path(s) via robots.txt/sitemap.xml")
                urls.extend(extra)
                findings["passive_discovery"] = extra
            else:
                logger.warn("No extra paths found via robots.txt/sitemap.xml")

        if args.swagger or run_all:
            logger.info("Looking for Swagger / OpenAPI definitions...")
            discovery = SwaggerDiscovery(engine, rate_limiter)
            found = await discovery.discover(target)
            if found:
                logger.success(f"Spec found at {found['source_url']}")
                endpoints = discovery.extract_endpoints(found["spec"], target)
                logger.info(f"Extracted {len(endpoints)} endpoint(s) from the spec")
                urls.extend(e["url"] for e in endpoints)
                findings["swagger"] = {"source_url": found["source_url"], "endpoints": endpoints}
            else:
                logger.warn("No Swagger/OpenAPI definition found at common paths")

        urls = sorted(set(urls))

        if urls:
            logger.info(f"Baseline scan of {len(urls)} endpoint(s)...")
            findings["baseline"] = await baseline_scan(
                engine, rate_limiter, urls, args.method, not args.no_grep, args.quiet
            )

        if args.exposures or run_all:
            logger.info("Probing common sensitive-file paths...")
            scanner = ExposureScanner(engine, rate_limiter)
            hits = await scanner.check_sensitive_files(target)
            findings["sensitive_files"] = hits
            for h in hits:
                logger.critical(f"Exposed file: {h['url']}")

        if args.cors or run_all:
            if not urls:
                logger.warn("--cors needs at least one URL (pass -w, or use --discover/--swagger)")
            else:
                logger.info("Testing CORS behaviour...")
                cors = CORSDetector(engine, rate_limiter)
                cors_results = await cors.run(urls)
                flagged = [r for r in cors_results if r["flagged"] or r["reflects_origin"]]
                findings["cors"] = flagged
                for r in flagged:
                    logger.warn(f"CORS issue ({r['severity']}) at {r['url']}")

        if args.bola or run_all:
            if not (args.token_a and args.token_b):
                if args.bola:
                    logger.error("--bola requires both --token-a and --token-b")
            elif not urls:
                logger.warn("--bola needs at least one URL (pass -w)")
            else:
                logger.info("Running BOLA / IDOR differential test...")
                bola = BOLADetector(engine, args.token_a, args.token_b, rate_limiter)
                bola_results = await bola.run(urls, args.method)
                flagged = [r for r in bola_results if r["flagged"]]
                findings["bola"] = flagged
                for r in flagged:
                    logger.warn(f"Needs manual review at {r['url']}: {r['reason']}")

    report_data = {
        "tool": "Ninja-API-Hunter v4.0",
        "target": target,
        "scanned_at": datetime.now().isoformat(),
        "findings": findings,
    }

    if not args.quiet:
        baseline = findings.get("baseline", [])
        secret_count = sum(len(e.get("secrets", [])) for e in baseline)
        logger.success(f"Done -- {len(baseline)} endpoint(s) checked, {secret_count} potential secret(s) flagged")

    if args.output:
        path = reporter.export(report_data, args.output, args.format)
        logger.success(f"Report written to {path}")

    return report_data


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        logger.warn("Scan interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
