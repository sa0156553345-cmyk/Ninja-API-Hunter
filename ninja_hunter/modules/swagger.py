"""
Ninja-API-Hunter v4.0
Swagger / OpenAPI discovery and parsing.

Looks for a published API spec at common paths, parses it (JSON or
YAML), and expands "paths" into a concrete list of URL + method pairs
that the rest of the toolkit can scan.
"""
import json

try:
    import yaml
except ImportError:
    yaml = None

from ..config import SWAGGER_PATHS

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}


class SwaggerDiscovery:
    def __init__(self, engine, rate_limiter=None):
        self.engine = engine
        self.rate_limiter = rate_limiter

    async def discover(self, base_url):
        base = base_url.rstrip("/")
        for path in SWAGGER_PATHS:
            url = f"{base}/{path}"
            resp = await self.engine.request("GET", url, rate_limiter=self.rate_limiter)
            if resp.get("status") == 200 and resp.get("body"):
                parsed = self._parse(resp["body"])
                if isinstance(parsed, dict) and ("paths" in parsed or "swagger" in parsed or "openapi" in parsed):
                    return {"source_url": url, "spec": parsed}
        return None

    @staticmethod
    def _parse(body):
        body = (body or "").strip()
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            pass
        if yaml:
            try:
                return yaml.safe_load(body)
            except Exception:
                pass
        return None

    @staticmethod
    def extract_endpoints(spec, base_url):
        endpoints = []
        if not isinstance(spec, dict) or "paths" not in spec:
            return endpoints

        base = base_url.rstrip("/")
        base_path = str(spec.get("basePath", "")).rstrip("/")

        for path, methods in spec["paths"].items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                method_upper = method.upper()
                if method_upper not in VALID_METHODS:
                    continue
                full_path = f"{base_path}{path}" if base_path else path
                params, summary = [], ""
                if isinstance(details, dict):
                    summary = details.get("summary", "")
                    params = [p.get("name") for p in details.get("parameters", []) if isinstance(p, dict)]
                endpoints.append({
                    "url": f"{base}{full_path}",
                    "method": method_upper,
                    "parameters": params,
                    "summary": summary,
                })
        return endpoints
