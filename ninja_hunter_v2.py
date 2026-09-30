#!/usr/bin/env python3
"""
Ninja-API-Hunter v2.0
Advanced API Security Scanner
Optimized for Termux + Mobile Bug Bounty
"""

import asyncio
import aiohttp
import argparse
import json
import re
import sys
import time
from datetime import datetime
from collections import defaultdict

# ═══════════════════════════════════════════
# Colors & Styling
# ═══════════════════════════════════════════

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @staticmethod
    def banner():
        return f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║         🥷 NINJA API HUNTER v2.0                          ║
║         Advanced API Security Scanner                     ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""

# ═══════════════════════════════════════════
# Sensitive Data Patterns
# ═══════════════════════════════════════════

SENSITIVE_PATTERNS = {
    "API Key": [
        r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        r'x-api-key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
    ],
    "AWS Access Key": [
        r'AKIA[0-9A-Z]{16}',
    ],
    "AWS Secret Key": [
        r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
    ],
    "JWT Token": [
        r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    ],
    "Bearer Token": [
        r'Bearer\s+[a-zA-Z0-9_\-\.=]{20,}',
        r'access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})',
    ],
    "GitHub Token": [
        r'ghp_[A-Za-z0-9]{36}',
        r'gho_[A-Za-z0-9]{36}',
        r'github_pat_[A-Za-z0-9_]{82}',
    ],
    "Google API Key": [
        r'AIza[0-9A-Za-z\-_]{35}',
    ],
    "Slack Token": [
        r'xox[baprs]-[A-Za-z0-9\-]{10,}',
    ],
    "Stripe Key": [
        r'sk_live_[A-Za-z0-9]{24}',
        r'pk_live_[A-Za-z0-9]{24}',
    ],
    "Private Key": [
        r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
    ],
    "Database URL": [
        r'(mongodb|postgres|mysql|redis)://[^\s@]+:[^\s@]+@[^\s]+',
    ],
    "Email + Password": [
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\']?\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*()]{6,}',
    ],
    "Internal IP": [
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
    ],
    "Admin Endpoint": [
        r'"admin"\s*:\s*true',
        r'"is_admin"\s*:\s*true',
        r'"role"\s*:\s*"admin"',
    ],
    "SSN Pattern": [
        r'\b\d{3}-\d{2}-\d{4}\b',
    ],
    "Credit Card": [
        r'\b4[0-9]{12}(?:[0-9]{3})?\b',
        r'\b5[1-5][0-9]{14}\b',
    ],
}

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

# ═══════════════════════════════════════════
# Async Scanner Engine
# ═══════════════════════════════════════════

class NinjaScanner:
    def __init__(self, args):
        self.args = args
        self.results = []
        self.findings = defaultdict(list)
        self.session = None
        self.semaphore = None
        
    async def init_session(self):
        timeout = aiohttp.ClientTimeout(total=self.args.timeout)
        connector = aiohttp.TCPConnector(
            limit=self.args.threads,
            ssl=False
        )
        
        headers = {
            'User-Agent': self.args.user_agent,
            'Accept': '*/*',
        }
        
        if self.args.headers:
            for h in self.args.headers:
                if ':' in h:
                    key, value = h.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers
        )
        
    async def close_session(self):
        if self.session:
            await self.session.close()
    
    async def scan_endpoint(self, url, method='GET'):
        async with self.semaphore:
            try:
                async with self.session.request(
                    method, url, 
                    proxy=self.args.proxy,
                    allow_redirects=True,
                    data=self.args.data if method != 'GET' else None
                ) as response:
                    
                    body = await response.text()
                    headers = dict(response.headers)
                    
                    result = {
                        'url': url,
                        'method': method,
                        'status': response.status,
                        'length': len(body),
                        'content_type': headers.get('Content-Type', ''),
                        'headers': headers,
                        'body': body[:5000],
                        'sensitive_findings': []
                    }
                    
                    if self.args.extract:
                        findings = self.extract_sensitive(body)
                        result['sensitive_findings'] = findings
                        for finding in findings:
                            self.findings[finding['type']].append({
                                'url': url,
                                'match': finding['match'][:100]
                            })
                    
                    self.results.append(result)
                    
                    status_color = self.get_status_color(response.status)
                    has_json = 'json' in result['content_type'].lower()
                    
                    if response.status == 200 and has_json:
                        symbol = f"{Colors.GREEN}[+] VULNERABLE"
                    elif response.status in [401, 403]:
                        symbol = f"{Colors.YELLOW}[-] PROTECTED"
                    elif response.status < 300:
                        symbol = f"{Colors.CYAN}[~] ALIVE"
                    elif response.status < 400:
                        symbol = f"{Colors.BLUE}[→] REDIRECT"
                    else:
                        symbol = f"{Colors.RED}[✗] DEAD"
                    
                    if not self.args.quiet:
                        print(f"{symbol}{Colors.END} [{status_color}{response.status}{Colors.END}] "
                              f"{method:7} {url}")
                    
                    if result['sensitive_findings']:
                        print(f"  {Colors.RED}{Colors.BOLD}🚨 CRITICAL FINDINGS:{Colors.END}")
                        for f in result['sensitive_findings']:
                            print(f"     {Colors.RED}→ {f['type']}{Colors.END}")
                    
                    return result
                    
            except asyncio.TimeoutError:
                if self.args.verbose:
                    print(f"{Colors.RED}[⏱] TIMEOUT: {url}{Colors.END}")
            except Exception as e:
                if self.args.verbose:
                    print(f"{Colors.RED}[✗] ERROR {url}: {str(e)[:50]}{Colors.END}")
    
    def extract_sensitive(self, body):
        findings = []
        for vuln_type, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, body, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': vuln_type,
                        'match': match.group(0),
                        'position': match.start()
                    })
                    break
        return findings
    
    @staticmethod
    def get_status_color(status):
        if status < 300:
            return Colors.GREEN
        elif status < 400:
            return Colors.BLUE
        elif status < 500:
            return Colors.YELLOW
        return Colors.RED
    
    async def run_scan(self, urls):
        self.semaphore = asyncio.Semaphore(self.args.threads)
        
        print(f"{Colors.CYAN}[*] Scanning {len(urls)} endpoints...{Colors.END}")
        print(f"{Colors.CYAN}[*] Method: {self.args.method}{Colors.END}")
        print(f"{Colors.CYAN}[*] Threads: {self.args.threads}{Colors.END}")
        print(f"{Colors.CYAN}[*] Target: {self.args.target}{Colors.END}")
        print(f"{Colors.CYAN}[*] Started: {datetime.now().strftime('%H:%M:%S')}{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.END}\n")
        
        start_time = time.time()
        tasks = [self.scan_endpoint(url, self.args.method) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        elapsed = time.time() - start_time
        print(f"\n{Colors.CYAN}{'─' * 60}{Colors.END}")
        print(f"{Colors.GREEN}[✓] Scan completed in {elapsed:.2f}s{Colors.END}")
        print(f"{Colors.GREEN}[✓] Speed: {len(urls)/elapsed:.1f} req/s{Colors.END}")
        
        self.print_summary()
        
        if self.args.output:
            self.export_results()
    
    def print_summary(self):
        alive = sum(1 for r in self.results if r['status'] < 400)
        vulnerable = sum(1 for r in self.results if r['status'] == 200 
                        and 'json' in r['content_type'].lower())
        protected = sum(1 for r in self.results if r['status'] in [401, 403])
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════╗")
        print(f"║         SCAN SUMMARY             ║")
        print(f"╚══════════════════════════════════╝{Colors.END}")
        print(f"{Colors.WHITE}Total Endpoints: {len(self.results)}{Colors.END}")
        print(f"{Colors.GREEN}Alive (2xx/3xx): {alive}{Colors.END}")
        print(f"{Colors.GREEN}JSON Exposed: {vulnerable}{Colors.END}")
        print(f"{Colors.YELLOW}Protected: {protected}{Colors.END}")
        
        if self.findings:
            print(f"\n{Colors.RED}{Colors.BOLD}🚨 SENSITIVE FINDINGS:{Colors.END}")
            for vuln_type, items in self.findings.items():
                print(f"  {Colors.RED}• {vuln_type}: {len(items)} matches{Colors.END}")
                for item in items[:3]:
                    print(f"    {Colors.YELLOW}↳ {item['url'][:60]}{Colors.END}")
    
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
                        'tool': 'Ninja-API-Hunter v2.0'
                    },
                    'findings': dict(self.findings),
                    'results': [
                        {k: v for k, v in r.items() if k != 'body'} 
                        for r in self.results
                    ]
                }, f, indent=2, ensure_ascii=False)
        
        elif self.args.output == 'csv':
            import csv
            filename = f"ninja_scan_{timestamp}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Method', 'Status', 'Length', 'Content-Type', 'Sensitive'])
                for r in self.results:
                    sensitive = ','.join(set(f['type'] for f in r['sensitive_findings']))
                    writer.writerow([
                        r['url'], r['method'], r['status'], 
                        r['length'], r['content_type'], sensitive
                    ])
        
        print(f"{Colors.GREEN}[✓] Results saved to: {filename}{Colors.END}")

# ═══════════════════════════════════════════
# CLI Arguments
# ═══════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description='🥷 Ninja-API-Hunter v2.0 - Advanced API Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt
  
  # With POST method and JSON data
  python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt -m POST -d '{"user":"admin"}'
  
  # With auth headers
  python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt \\
    -H "Authorization: Bearer eyJ0eXAi..." -H "X-API-Key: abc123"
  
  # With proxy (Burp Suite)
  python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt --proxy http://127.0.0.1:8080
  
  # Export results
  python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt -o json
  
  # Full package
  python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt \\
    -m POST -H "Authorization: Bearer token" --extract --threads 50 -o json
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target base URL (e.g., https://api.target.com)')
    parser.add_argument('-w', '--wordlist', required=True,
                       help='Path to wordlist file')
    
    parser.add_argument('-m', '--method', default='GET',
                       choices=HTTP_METHODS,
                       help='HTTP method (default: GET)')
    parser.add_argument('-d', '--data', default=None,
                       help='Request body data (for POST/PUT)')
    
    parser.add_argument('-H', '--headers', action='append', default=[],
                       help='Custom headers (can be used multiple times)')
    
    parser.add_argument('--threads', type=int, default=20,
                       help='Number of concurrent requests (default: 20)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    
    parser.add_argument('--extract', action='store_true',
                       help='Extract sensitive data from responses')
    parser.add_argument('--proxy', default=None,
                       help='Proxy URL (e.g., http://127.0.0.1:8080 for Burp)')
    
    parser.add_argument('--user-agent', 
                       default='Ninja-API-Hunter/2.0',
                       help='Custom User-Agent')
    
    parser.add_argument('-o', '--output', choices=['json', 'csv'], default=None,
                       help='Export results format')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode (minimal output)')
    
    return parser.parse_args()

# ═══════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════

async def main():
    args = parse_args()
    
    print(Colors.banner())
    
    try:
        with open(args.wordlist, 'r', encoding='utf-8') as f:
            paths = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}[✗] Wordlist not found: {args.wordlist}{Colors.END}")
        sys.exit(1)
    
    base = args.target.rstrip('/')
    urls = [f"{base}/{path.lstrip('/')}" for path in paths]
    
    scanner = NinjaScanner(args)
    await scanner.init_session()
    
    try:
        await scanner.run_scan(urls)
    finally:
        await scanner.close_session()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(0)
