"""
Ninja-API-Hunter v4.0
Sensitive-exposure scanning: known-path probing, secret/stack-trace
pattern grepping, and missing security-header checks.
"""
import re

from ..config import SENSITIVE_FILES, SENSITIVE_PATTERNS, STACK_TRACE_PATTERNS, SECURITY_HEADERS


class ExposureScanner:
    def __init__(self, engine, rate_limiter=None):
        self.engine = engine
        self.rate_limiter = rate_limiter

    async def check_sensitive_files(self, base_url):
        """Probe a fixed list of commonly-exposed paths (extra requests,
        separate from whatever wordlist the user supplied)."""
        base = base_url.rstrip("/")
        hits = []
        for path in SENSITIVE_FILES:
            url = f"{base}/{path}"
            resp = await self.engine.request("GET", url, rate_limiter=self.rate_limiter)
            if resp.get("status") == 200 and resp.get("body"):
                hits.append({"url": url, "status": 200, "size": len(resp["body"])})
        return hits

    @staticmethod
    def scan_body_for_secrets(body):
        findings = []
        if not body:
            return findings
        for vuln_type, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    findings.append({"type": vuln_type, "match": match.group(0)[:80]})
                    break
        return findings

    @staticmethod
    def scan_body_for_stack_traces(body):
        if not body:
            return []
        return [p for p in STACK_TRACE_PATTERNS if re.search(p, body)]

    @staticmethod
    def check_security_headers(headers):
        present = {str(k).lower() for k in (headers or {})}
        return [h for h in SECURITY_HEADERS if h.lower() not in present]
