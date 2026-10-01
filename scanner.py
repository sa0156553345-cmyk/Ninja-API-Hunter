"""Core async scan engine."""

import asyncio
import csv
import json
import ssl
import time
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

import aiohttp

from .colors import Colors
from .detectors import extract_sensitive, detect_exposure, check_security_headers
from .discovery import (
    COMMON_API_DOC_PATHS,
    parse_robots_txt,
    parse_sitemap_xml,
    extract_paths_from_openapi,
    extract_links_from_body,
)

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']


class NinjaScanner:
    def __init__(self, args):
        self.args = args
        self.results = []
        self.findings = defaultdict(list)
        self.session = None
        self.semaphore = None
        self._visited = set()
        self._queued = set()

    # ── setup ────────────────────────────────────────────────
    async def init_session(self):
        timeout = aiohttp.ClientTimeout(total=self.args.timeout)

        if self.args.insecure:
            print(f"{Colors.YELLOW}[!] --insecure set: TLS certificate "
                  f"verification is OFF. Only use this against targets you "
                  f"trust (e.g. local self-signed labs).{Colors.END}")
            ssl_context = False
        else:
            ssl_context = ssl.create_default_context()

        connector = aiohttp.TCPConnector(limit=self.args.threads, ssl=ssl_context)

        headers = {'User-Agent': self.args.user_agent, 'Accept': '*/*'}
        for h in self.args.headers:
            if ':' in h:
                key, value = h.split(':', 1)
                headers[key.strip()] = value.strip()

        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers)

    async def close_session(self):
        if self.session:
            await self.session.close()

    # ── discovery phase ──────────────────────────────────────
    async def discover(self, base: str) -> list[str]:
        """Fetch robots.txt / sitemap.xml / common API docs and turn them
        into extra candidate paths, on top of whatever the wordlist gave us."""
        if not self.args.discover:
            return []

        discovered: set[str] = set()
        probe_targets = ["robots.txt", "sitemap.xml"] + COMMON_API_DOC_PATHS

        print(f"{Colors.CYAN}[*] Discovery: checking robots.txt, sitemap.xml, "
              f"and {len(COMMON_API_DOC_PATHS)} common API doc paths...{Colors.END}")

        async def probe(path):
            url = f"{base}/{path}"
            try:
                async with self.session.get(url, proxy=self.args.proxy) as resp:
                    if resp.status != 200:
                        return
                    text = await resp.text()
                    if path == "robots.txt":
                        discovered.update(parse_robots_txt(text))
                    elif path == "sitemap.xml":
                        for loc in parse_sitemap_xml(text):
                            discovered.add(urlparse(loc).path.lstrip("/"))
                    elif "swagger" in path or "openapi" in path or "api-docs" in path:
                        discovered.update(extract_paths_from_openapi(text))
            except Exception:
                pass

        await asyncio.gather(*(probe(p) for p in probe_targets), return_exceptions=True)

        if discovered:
            print(f"{Colors.GREEN}[+] Discovery found {len(discovered)} extra "
                  f"candidate path(s){Colors.END}")
        return sorted(discovered)

    # ── single request with retry/backoff ───────────────────
    async def _request_with_retry(self, url, method):
        last_exc = None
        for attempt in range(self.args.retries + 1):
            try:
                return await self.session.request(
                    method, url,
                    proxy=self.args.proxy,
                    allow_redirects=True,
                    data=self.args.data if method != 'GET' else None,
                )
            except (asyncio.TimeoutError, aiohttp.ClientError) as exc:
                last_exc = exc
                if attempt < self.args.retries:
                    await asyncio.sleep(self.args.backoff * (2 ** attempt))
        raise last_exc

    async def scan_endpoint(self, url, method='GET', depth=0):
        if url in self._visited:
            return None
        self._visited.add(url)

        async with self.semaphore:
            if self.args.delay:
                await asyncio.sleep(self.args.delay)
            try:
                response = await self._request_with_retry(url, method)
            except Exception as e:
                if self.args.verbose:
                    print(f"{Colors.RED}[✗] ERROR {url}: {str(e)[:60]}{Colors.END}")
                return None

            async with response:
                body = await response.text(errors="replace")
                headers = dict(response.headers)
                content_type = headers.get('Content-Type', '')

                sensitive = extract_sensitive(body) if self.args.extract else []
                exposure = detect_exposure(url, response.status, content_type, body) if self.args.extract else []
                header_findings = (
                    check_security_headers(headers)
                    if self.args.extract and "html" in content_type.lower()
                    else []
                )
                all_findings = sensitive + exposure + header_findings

                result = {
                    'url': url, 'method': method, 'status': response.status,
                    'length': len(body), 'content_type': content_type,
                    'headers': headers, 'body': body[:5000],
                    'sensitive_findings': all_findings,
                }
                self.results.append(result)
                for f in all_findings:
                    self.findings[f['type']].append({'url': url, 'match': f['match'][:100]})

                self._print_line(url, method, response.status, content_type, all_findings)

                if self.args.recursive and depth < self.args.max_depth and response.status == 200:
                    for link in extract_links_from_body(body, content_type, url):
                        if link not in self._visited and link not in self._queued:
                            self._queued.add(link)
                            asyncio.create_task(self.scan_endpoint(link, 'GET', depth + 1))

                return result

    def _print_line(self, url, method, status, content_type, findings):
        if self.args.quiet:
            return
        has_json = 'json' in content_type.lower()
        if status == 200 and has_json:
            symbol = f"{Colors.GREEN}[+] EXPOSED"
        elif status in (401, 403):
            symbol = f"{Colors.YELLOW}[-] PROTECTED"
        elif status < 300:
            symbol = f"{Colors.CYAN}[~] ALIVE"
        elif status < 400:
            symbol = f"{Colors.BLUE}[→] REDIRECT"
        else:
            symbol = f"{Colors.RED}[✗] DEAD"

        status_color = Colors.GREEN if status < 300 else Colors.YELLOW if status < 500 else Colors.RED
        print(f"{symbol}{Colors.END} [{status_color}{status}{Colors.END}] {method:7} {url}")
        if findings:
            print(f"  {Colors.RED}{Colors.BOLD}🚨 FINDINGS:{Colors.END}")
            for f in findings:
                print(f"     {Colors.RED}→ {f['type']}{Colors.END}")

    # ── orchestration ────────────────────────────────────────
    async def run_scan(self, base_url: str, wordlist_paths: list[str]):
        self.semaphore = asyncio.Semaphore(self.args.threads)
        base = base_url.rstrip('/')

        extra = await self.discover(base)
        all_paths = list(dict.fromkeys(wordlist_paths + extra))  # dedupe, keep order
        urls = [f"{base}/{p.lstrip('/')}" for p in all_paths]

        print(f"{Colors.CYAN}[*] Scanning {len(urls)} endpoints "
              f"({len(wordlist_paths)} wordlist + {len(extra)} discovered)...{Colors.END}")
        print(f"{Colors.CYAN}[*] Method: {self.args.method} | Threads: {self.args.threads} "
              f"| TLS verify: {'OFF' if self.args.insecure else 'ON'}{Colors.END}")
        print(f"{Colors.CYAN}[*] Started: {datetime.now().strftime('%H:%M:%S')}{Colors.END}\n")

        start = time.time()
        tasks = [asyncio.create_task(self.scan_endpoint(u, self.args.method)) for u in urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        # recursive discovery spawns its own tasks as results come in, so
        # keep draining until nothing new is pending (not just one pass)
        while True:
            pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
            if not pending:
                break
            await asyncio.gather(*pending, return_exceptions=True)

        elapsed = time.time() - start
        print(f"\n{Colors.GREEN}[✓] Scan completed in {elapsed:.2f}s "
              f"({len(self.results)} responses, {len(self.results)/elapsed:.1f} req/s){Colors.END}")

        self.print_summary()
        if self.args.output:
            self.export_results()

    def print_summary(self):
        alive = sum(1 for r in self.results if r['status'] < 400)
        exposed = sum(1 for r in self.results if r['status'] == 200 and 'json' in r['content_type'].lower())
        protected = sum(1 for r in self.results if r['status'] in (401, 403))

        print(f"\n{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════╗")
        print("║         SCAN SUMMARY              ║")
        print(f"╚══════════════════════════════════╝{Colors.END}")
        print(f"{Colors.WHITE}Total Endpoints: {len(self.results)}{Colors.END}")
        print(f"{Colors.GREEN}Alive (2xx/3xx): {alive}{Colors.END}")
        print(f"{Colors.GREEN}JSON Exposed:    {exposed}{Colors.END}")
        print(f"{Colors.YELLOW}Protected:       {protected}{Colors.END}")

        if self.findings:
            print(f"\n{Colors.RED}{Colors.BOLD}🚨 FINDINGS BY TYPE:{Colors.END}")
            for vuln_type, items in self.findings.items():
                print(f"  {Colors.RED}• {vuln_type}: {len(items)} match(es){Colors.END}")
                for item in items[:3]:
                    print(f"    {Colors.YELLOW}↳ {item['url'][:70]}{Colors.END}")

    def export_results(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if self.args.output == 'json':
            filename = f"ninja_scan_{timestamp}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({
                    'scan_info': {
                        'target': self.args.target,
                        'date': datetime.now().isoformat(),
                        'total_endpoints': len(self.results),
                        'tool': 'Ninja-API-Hunter v3.0',
                    },
                    'findings': dict(self.findings),
                    'results': [{k: v for k, v in r.items() if k != 'body'} for r in self.results],
                }, f, indent=2, ensure_ascii=False)
        else:
            filename = f"ninja_scan_{timestamp}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Method', 'Status', 'Length', 'Content-Type', 'Findings'])
                for r in self.results:
                    types = ','.join(sorted({f['type'] for f in r['sensitive_findings']}))
                    writer.writerow([r['url'], r['method'], r['status'], r['length'], r['content_type'], types])
        print(f"{Colors.GREEN}[✓] Results saved to: {filename}{Colors.END}")
