"""
Ninja-API-Hunter v4.0
Passive discovery: pulls extra candidate paths out of robots.txt and
sitemap.xml so they get added to the scan without the user needing to
already know about them. This is the v3.0 "smart discovery" behaviour,
carried forward and kept separate from Swagger/OpenAPI parsing
(modules/swagger.py handles that).
"""
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse


class PassiveDiscovery:
    def __init__(self, engine, rate_limiter=None):
        self.engine = engine
        self.rate_limiter = rate_limiter

    async def from_robots_txt(self, base_url):
        base = base_url.rstrip("/")
        resp = await self.engine.request("GET", f"{base}/robots.txt", rate_limiter=self.rate_limiter)
        if resp.get("status") != 200 or not resp.get("body"):
            return []
        return self.parse_robots_txt(resp["body"])

    @staticmethod
    def parse_robots_txt(body):
        paths = []
        for line in body.splitlines():
            line = line.strip()
            match = re.match(r"(?i)(disallow|allow|sitemap)\s*:\s*(\S+)", line)
            if match:
                value = match.group(2)
                if value and value != "/" and not value.lower().startswith("http"):
                    paths.append(value)
        return sorted(set(paths))

    async def from_sitemap_xml(self, base_url, sitemap_path="sitemap.xml"):
        base = base_url.rstrip("/")
        resp = await self.engine.request("GET", f"{base}/{sitemap_path}", rate_limiter=self.rate_limiter)
        if resp.get("status") != 200 or not resp.get("body"):
            return []
        return self.parse_sitemap_xml(resp["body"])

    @staticmethod
    def parse_sitemap_xml(body):
        try:
            root = ET.fromstring(body)
            urls = []
            for el in root.iter():
                tag = el.tag.split("}")[-1]  # strip XML namespace, if any
                if tag == "loc" and el.text:
                    urls.append(el.text.strip())
            return sorted(set(urls))
        except ET.ParseError:
            # Fall back to a simple regex for malformed/non-strict XML
            return sorted(set(re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body)))

    async def discover_all(self, base_url):
        """Return same-host URLs pulled from robots.txt + sitemap.xml."""
        base = base_url.rstrip("/")
        host = urlparse(base_url).netloc

        robots_paths = await self.from_robots_txt(base_url)
        sitemap_urls = await self.from_sitemap_xml(base_url)

        candidates = [f"{base}/{p.lstrip('/')}" for p in robots_paths]
        for url in sitemap_urls:
            candidates.append(url if url.startswith("http") else f"{base}/{url.lstrip('/')}")

        same_host = [u for u in candidates if urlparse(u).netloc in ("", host)]
        return sorted(set(same_host))
