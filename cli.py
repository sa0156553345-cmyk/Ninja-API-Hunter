import argparse
import asyncio
import sys

from .colors import Colors
from .scanner import NinjaScanner, HTTP_METHODS


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description='🥷 Ninja-API-Hunter v3.0 - Async REST API Recon Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  ninja-hunter -t https://api.target.com -w wordlist.txt

  # Smart discovery + recursive + extraction
  ninja-hunter -t https://api.target.com -w wordlist.txt \\
    --discover --recursive --extract

  # Self-signed / local lab target (disables TLS verification)
  ninja-hunter -t https://192.168.1.50 -w wordlist.txt --insecure

  # Through Burp Suite, politely rate-limited
  ninja-hunter -t https://api.target.com -w wordlist.txt \\
    --proxy http://127.0.0.1:8080 --delay 0.2 --threads 10

Only scan targets you own or are explicitly authorized to test.
        """,
    )

    parser.add_argument('-t', '--target', required=True, help='Target base URL')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist file')

    parser.add_argument('-m', '--method', default='GET', choices=HTTP_METHODS)
    parser.add_argument('-d', '--data', default=None, help='Request body (POST/PUT)')
    parser.add_argument('-H', '--headers', action='append', default=[], help='Custom header, repeatable')

    parser.add_argument('--threads', type=int, default=20, help='Concurrent requests (default: 20)')
    parser.add_argument('--timeout', type=int, default=10, help='Per-request timeout, seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=0.0, help='Fixed delay between requests, seconds')
    parser.add_argument('--retries', type=int, default=1, help='Retries on timeout/connection error (default: 1)')
    parser.add_argument('--backoff', type=float, default=0.5, help='Base backoff seconds between retries (default: 0.5)')

    parser.add_argument('--insecure', action='store_true',
                         help='Disable TLS certificate verification (default: verification is ON)')

    parser.add_argument('--discover', action='store_true',
                         help='Check robots.txt/sitemap.xml/common API docs and add what they reveal to the scan')
    parser.add_argument('--recursive', action='store_true',
                         help='Follow same-host links found in 200 responses')
    parser.add_argument('--max-depth', type=int, default=2, help='Max recursion depth (default: 2)')

    parser.add_argument('--extract', action='store_true', help='Flag secrets and passive exposure signatures')
    parser.add_argument('--proxy', default=None, help='Proxy URL, e.g. http://127.0.0.1:8080 for Burp')
    parser.add_argument('--user-agent', default='Ninja-API-Hunter/3.0')
    parser.add_argument('-o', '--output', choices=['json', 'csv'], default=None)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-q', '--quiet', action='store_true')

    return parser.parse_args(argv)


async def _run(args):
    print(Colors.banner())
    try:
        with open(args.wordlist, 'r', encoding='utf-8') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"{Colors.RED}[✗] Wordlist not found: {args.wordlist}{Colors.END}")
        sys.exit(1)

    scanner = NinjaScanner(args)
    await scanner.init_session()
    try:
        await scanner.run_scan(args.target, paths)
    finally:
        await scanner.close_session()


def main():
    args = parse_args()
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(0)


if __name__ == '__main__':
    main()
