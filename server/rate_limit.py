import threading
import time


class SlidingWindowLimiter:
    """Simple per-IP sliding window rate limiter (thread-safe)."""

    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window = window_seconds
        self._by_key = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._by_key.setdefault(key, [])
            q[:] = [t for t in q if now - t < self.window]
            if len(q) >= self.max_events:
                return False
            q.append(now)
            return True
