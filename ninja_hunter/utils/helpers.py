"""
Ninja-API-Hunter v4.0
Small, dependency-free helper functions. Kept separate from cli.py so
they (and the test suite) never need aiohttp just to be imported.
"""


def parse_headers(header_list):
    """Turn a list of 'Key: Value' strings into a headers dict."""
    headers = {}
    for h in header_list or []:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def load_wordlist(path):
    """Read a wordlist file, stripping blank lines and comments."""
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def classify(status):
    """Classify an HTTP status code into a coarse scan state."""
    if status is None:
        return "ERROR"
    if status in (401, 403):
        return "PROTECTED"
    if status < 300:
        return "ALIVE"
    if status < 400:
        return "REDIRECT"
    return "DEAD"
