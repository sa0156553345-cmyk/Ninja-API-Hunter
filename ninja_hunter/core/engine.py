"""
Ninja-API-Hunter v4.0
Async HTTP engine built on aiohttp. Every module talks to the network
exclusively through this class, so SSL verification, proxying,
timeouts and custom headers are applied consistently everywhere.
"""
import asyncio
import aiohttp


class RequestEngine:
    def __init__(self, timeout=10, verify_ssl=True, proxy=None,
                 user_agent="Ninja-API-Hunter/4.0", extra_headers=None, threads=20):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.threads = max(1, threads)
        self.headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if extra_headers:
            self.headers.update(extra_headers)
        self.session = None
        self.semaphore = asyncio.Semaphore(self.threads)

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=self.verify_ssl)
        self.session = aiohttp.ClientSession(
            timeout=self.timeout, headers=self.headers, connector=connector
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def request(self, method, url, headers=None, data=None, rate_limiter=None):
        """Send one request through the shared session.

        Always returns a dict with at least url/method/status/headers/body
        keys, even on failure, so callers never need to guard against
        missing keys.
        """
        async with self.semaphore:
            if rate_limiter:
                await rate_limiter.wait_if_needed()
            try:
                async with self.session.request(
                    method, url, headers=headers, data=data,
                    proxy=self.proxy, allow_redirects=True,
                ) as resp:
                    body = await resp.text()
                    result = {
                        "url": str(resp.url),
                        "method": method,
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                    }
                    if rate_limiter:
                        rate_limiter.record(resp.status)
                    return result
            except asyncio.TimeoutError:
                return {"url": url, "method": method, "status": None,
                        "headers": {}, "body": "", "error": "timeout"}
            except aiohttp.ClientError as e:
                return {"url": url, "method": method, "status": None,
                        "headers": {}, "body": "", "error": str(e)}
            except Exception as e:
                return {"url": url, "method": method, "status": None,
                        "headers": {}, "body": "", "error": str(e)}
