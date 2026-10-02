"""
Ninja-API-Hunter v4.0
CORS misconfiguration detector.

Sends a request with a third-party Origin header and checks whether
the server reflects it back in Access-Control-Allow-Origin -- which is
only dangerous when combined with Access-Control-Allow-Credentials:
true, since that would let a page on the attacker's origin make
authenticated requests on a victim's behalf.
"""

TEST_ORIGIN = "https://evil.com"


class CORSDetector:
    def __init__(self, engine, rate_limiter=None, test_origin=TEST_ORIGIN):
        self.engine = engine
        self.rate_limiter = rate_limiter
        self.test_origin = test_origin

    async def test_endpoint(self, url, extra_headers=None):
        headers = {"Origin": self.test_origin}
        if extra_headers:
            headers.update(extra_headers)

        resp = await self.engine.request("GET", url, headers=headers, rate_limiter=self.rate_limiter)
        resp_headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}

        acao = resp_headers.get("access-control-allow-origin")
        acac = resp_headers.get("access-control-allow-credentials", "").lower() == "true"
        reflects_origin = acao == self.test_origin
        wildcard_with_creds = acao == "*" and acac

        flagged = reflects_origin and acac
        if flagged:
            severity = "high"
        elif reflects_origin or wildcard_with_creds:
            severity = "medium"
        else:
            severity = "none"

        return {
            "url": url,
            "status": resp.get("status"),
            "acao": acao,
            "acac": acac,
            "reflects_origin": reflects_origin,
            "flagged": flagged,
            "severity": severity,
        }

    async def run(self, urls):
        return [await self.test_endpoint(url) for url in urls]
