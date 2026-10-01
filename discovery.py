"""
Smart discovery — turns a static wordlist into a starting point instead of
the whole scan. Every function here parses text that was *already fetched*
and returns candidate paths; none of them make requests themselves, so
they're trivial to unit test.
"""

import json
import re
from urllib.parse import urljoin, urlparse

# Common locations worth checking even if they're not in the wordlist —
# these are themselves just candidate paths to fetch, same as anything
# from wordlist.txt.
COMMON_API_DOC_PATHS = [
    "swagger.json", "swagger.yaml", "swagger.yml",
    "openapi.json", "openapi.yaml",
    "v1/swagger.json", "v2/swagger.json", "v3/api-docs",
    "api-docs", "api/swagger.json", "api/docs",
    "swagger-ui.html", "swagger-ui/index.html",
    "graphql", "graphiql",
    ".well-known/openapi.json",
]


def parse_robots_txt(text: str) -> list[str]:
    """Extract Disallow/Allow paths from a robots.txt body. These are paths
    the site operator cared enough about to hide from search engines —
    which makes them worth checking, not worth skipping."""
    paths = []
    for line in text.splitlines():
        line = line.strip()
        match = re.match(r'(?i)^(disallow|allow)\s*:\s*(\S+)', line)
        if match:
            path = match.group(2).strip()
            if path and path != "/":
                paths.append(path.lstrip("/"))
    # de-dupe, keep order
    seen = set()
    out = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def parse_sitemap_xml(text: str) -> list[str]:
    """Pull <loc> entries out of a sitemap.xml (or sitemap index) body."""
    return re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', text, re.IGNORECASE)


def extract_paths_from_openapi(text: str, base_url: str = "") -> list[str]:
    """Parse an OpenAPI/Swagger JSON doc and return every documented path.
    This is usually the single highest-value discovery source: it's the
    API's own map of itself. Falls back to [] on anything that isn't
    valid/relevant JSON rather than raising."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []

    if not isinstance(data, dict) or "paths" not in data:
        return []

    base_path = data.get("basePath", "").strip("/")
    out = []
    for path in data.get("paths", {}):
        clean = path.lstrip("/")
        out.append(f"{base_path}/{clean}".strip("/") if base_path else clean)
    return out


def extract_links_from_body(body: str, content_type: str, base_url: str) -> set[str]:
    """Best-effort extraction of same-host paths referenced inside a
    response, for bounded recursive discovery. Handles JSON string values
    and plain HTML href/src attributes; anything off-host is dropped."""
    host = urlparse(base_url).netloc
    candidates: set[str] = set()

    url_like = re.findall(r'["\'](/[a-zA-Z0-9/_\-.]{1,200})["\']', body)
    for u in url_like:
        candidates.add(u)

    if "html" in content_type.lower():
        for attr_url in re.findall(r'(?:href|src)=["\']([^"\']+)["\']', body):
            parsed = urlparse(attr_url)
            if parsed.netloc and parsed.netloc != host:
                continue
            if parsed.path:
                candidates.add(parsed.path)

    resolved = set()
    for c in candidates:
        resolved.add(urljoin(base_url, c))
    return resolved
