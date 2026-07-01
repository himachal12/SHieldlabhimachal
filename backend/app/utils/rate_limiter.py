"""
Rate Limiter — Token bucket, thread-safe.
Used by all web scanning modules.
"""

import time
import threading
from app.utils.logger import get_logger

logger = get_logger("rate_limiter")


class RateLimiter:
    def __init__(self, rate: float = 2.0, per: float = 1.0):
        self.rate = rate
        self.per = per
        self._allowance = rate
        self._last_check = time.monotonic()
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_check
            self._last_check = now
            self._allowance += elapsed * (self.rate / self.per)
            if self._allowance > self.rate:
                self._allowance = self.rate
            if self._allowance < 1.0:
                sleep_time = (1.0 - self._allowance) * (self.per / self.rate)
                logger.debug(f"Rate limiter sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)
                self._allowance = 0.0
            else:
                self._allowance -= 1.0


# Shared instances
web_scan_limiter = RateLimiter(rate=2, per=1.0)        # passive scanning
active_scan_limiter = RateLimiter(rate=0.5, per=1.0)   # active scanning (slower, more careful)