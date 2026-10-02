"""
Ninja-API-Hunter v4.0
BOLA / IDOR differential tester.

This module does NOT guess, brute-force, or steal credentials. It
expects two tokens for two accounts you are already authorized to use
against the target (for example, two test accounts in a bug bounty
program's sandbox), and checks whether the API enforces object-level
authorization consistently between them. A "flagged" result means the
endpoint deserves a human look -- it is not automatic proof of a
vulnerability.
"""


class BOLADetector:
    def __init__(self, engine, token_a, token_b, rate_limiter=None):
        self.engine = engine
        self.token_a = token_a
        self.token_b = token_b
        self.rate_limiter = rate_limiter

    async def test_endpoint(self, url, method="GET"):
        headers_a = {"Authorization": f"Bearer {self.token_a}"}
        headers_b = {"Authorization": f"Bearer {self.token_b}"}

        resp_a = await self.engine.request(method, url, headers=headers_a, rate_limiter=self.rate_limiter)
        resp_b = await self.engine.request(method, url, headers=headers_b, rate_limiter=self.rate_limiter)

        status_a = resp_a.get("status")
        status_b = resp_b.get("status")
        body_a = resp_a.get("body") or ""
        body_b = resp_b.get("body") or ""

        flagged = False
        reason = "Not enough information to compare"

        if status_a and status_b:
            if status_a == 200 and status_b == 200:
                flagged = True
                if self._similarity(body_a, body_b) > 0.95:
                    reason = "Both tokens received near-identical data -- verify object ownership is actually checked"
                else:
                    reason = "Both tokens received 200 OK -- confirm each account should be able to see this resource"
            elif status_a == 200 and status_b in (401, 403):
                reason = "Access control looks consistent (token B was denied)"
            elif status_b == 200 and status_a in (401, 403):
                reason = "Access control looks consistent (token A was denied)"
            else:
                reason = f"Inconclusive (status A={status_a}, status B={status_b})"

        return {
            "url": url,
            "method": method,
            "status_a": status_a,
            "status_b": status_b,
            "length_a": len(body_a),
            "length_b": len(body_b),
            "flagged": flagged,
            "reason": reason,
        }

    @staticmethod
    def _similarity(a, b):
        """Cheap character-overlap ratio -- no extra dependencies needed."""
        if not a or not b:
            return 0.0
        shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
        if not shorter:
            return 0.0
        matches = sum(1 for c1, c2 in zip(shorter, longer) if c1 == c2)
        return matches / len(longer)

    async def run(self, urls, method="GET"):
        return [await self.test_endpoint(url, method) for url in urls]
