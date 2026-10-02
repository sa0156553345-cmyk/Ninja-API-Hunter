"""
Ninja-API-Hunter v4.0
Adaptive rate limiter: backs off automatically on 429/503 responses
and recovers gradually once the target responds normally again.
"""
import asyncio


class AdaptiveRateLimiter:
    def __init__(self, base_delay=0.0, max_delay=5.0, backoff_factor=2.0,
                 min_backoff=0.25, recovery_step=0.1):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.min_backoff = min_backoff
        self.recovery_step = recovery_step
        self.consecutive_limited = 0

    async def wait_if_needed(self):
        if self.current_delay > 0:
            await asyncio.sleep(self.current_delay)

    def record(self, status_code):
        """Feed back the status code of the request that just completed."""
        if status_code in (429, 503):
            self.consecutive_limited += 1
            if self.current_delay <= 0:
                self.current_delay = self.min_backoff
            else:
                self.current_delay = min(self.max_delay, self.current_delay * self.backoff_factor)
        else:
            self.consecutive_limited = 0
            if self.current_delay > self.base_delay:
                self.current_delay = max(self.base_delay, self.current_delay - self.recovery_step)
