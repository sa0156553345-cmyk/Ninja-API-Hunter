"""
Passive detection logic.

Everything in this module is a pure function: give it a string / dict you
already fetched, get findings back. Nothing here makes a network request or
tries to exploit anything it finds — it only recognizes things that are
*already* exposed in a response. That's what keeps this a recon module
instead of an exploitation module.
"""

import re

# ─────────────────────────────────────────────
# Secret / sensitive-data patterns (unchanged from v2.0, lightly tidied)
# ─────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    "API Key": [
        r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        r'x-api-key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
    ],
    "AWS Access Key": [r'AKIA[0-9A-Z]{16}'],
    "AWS Secret Key": [
        r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
    ],
    "JWT Token": [r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'],
    "Bearer Token": [
        r'Bearer\s+[a-zA-Z0-9_\-\.=]{20,}',
        r'access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})',
    ],
    "GitHub Token": [
        r'ghp_[A-Za-z0-9]{36}',
        r'gho_[A-Za-z0-9]{36}',
        r'github_pat_[A-Za-z0-9_]{82}',
    ],
    "Google API Key": [r'AIza[0-9A-Za-z\-_]{35}'],
    "Slack Token": [r'xox[baprs]-[A-Za-z0-9\-]{10,}'],
    "Stripe Key": [r'sk_live_[A-Za-z0-9]{24}', r'pk_live_[A-Za-z0-9]{24}'],
    "Private Key": [r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'],
    "Database URL": [r'(mongodb|postgres|mysql|redis)://[^\s@]+:[^\s@]+@[^\s]+'],
    "Internal IP": [
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3})\b',
    ],
    "Admin Flag": [
        r'"admin"\s*:\s*true',
        r'"is_admin"\s*:\s*true',
        r'"role"\s*:\s*"admin"',
    ],
}


def extract_sensitive(body: str) -> list[dict]:
    """Scan a response body for secret-shaped strings. Returns one hit per
    pattern per type (not every occurrence) to keep output readable."""
    findings = []
    for vuln_type, patterns in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                findings.append({
                    "type": vuln_type,
                    "match": match.group(0),
                    "position": match.start(),
                })
    return findings


# ─────────────────────────────────────────────
# Passive exposure signatures — recognizing things that are already
# public, not probing for anything. No payloads, no exploitation.
# ─────────────────────────────────────────────

_GIT_HEAD_RE = re.compile(r'^ref:\s*refs/')
_ENV_LINE_RE = re.compile(r'^[A-Z_][A-Z0-9_]*\s*=\s*\S', re.MULTILINE)
_STACKTRACE_MARKERS = [
    "Traceback (most recent call last)",   # Python
    "at java.",                            # Java
    "Exception in thread",                 # Java
    ".php on line",                        # PHP
    "System.Exception",                    # .NET
    "Microsoft.AspNetCore",                # .NET
    "node_modules/", "at Object.<anonymous>",  # Node
]


def detect_exposure(url: str, status: int, content_type: str, body: str) -> list[dict]:
    """Recognize a handful of well-known 'this should not be public' shapes
    in an already-fetched response. Each check only fires on a positive
    content match, not just a matching path, to keep false positives low."""
    findings = []
    path = url.split("?", 1)[0].lower()

    if status == 200:
        if path.endswith("/.git/head") and _GIT_HEAD_RE.search(body):
            findings.append({
                "type": "Exposed .git/HEAD",
                "match": body.strip()[:60],
                "position": 0,
            })

        if path.endswith("/.env") and _ENV_LINE_RE.search(body):
            findings.append({
                "type": "Exposed .env file",
                "match": _ENV_LINE_RE.search(body).group(0)[:60],
                "position": 0,
            })

        if any(seg in path for seg in ("swagger.json", "openapi.json", "/v2/api-docs")):
            lowered = body.lower()
            if '"swagger"' in lowered or '"openapi"' in lowered:
                findings.append({
                    "type": "Public API schema (Swagger/OpenAPI)",
                    "match": path,
                    "position": 0,
                })

        for marker in _STACKTRACE_MARKERS:
            if marker in body:
                findings.append({
                    "type": "Verbose stack trace in response",
                    "match": marker,
                    "position": body.find(marker),
                })
                break  # one hit is enough to flag the endpoint

    return findings


_RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": "no HSTS — HTTPS downgrade is possible",
    "X-Content-Type-Options": "missing — browsers may MIME-sniff responses",
    "X-Frame-Options": "missing — page can likely be framed (clickjacking)",
    "Content-Security-Policy": "missing — no CSP baseline against injected scripts",
}


def check_security_headers(headers: dict) -> list[dict]:
    """Passive header hygiene check. Only meaningful for HTML/browser-facing
    endpoints, not raw JSON APIs — callers should filter by content-type."""
    lowered = {k.lower(): v for k, v in headers.items()}
    findings = []
    for header, note in _RECOMMENDED_HEADERS.items():
        if header.lower() not in lowered:
            findings.append({
                "type": f"Missing header: {header}",
                "match": note,
                "position": 0,
            })
    return findings
