"""In-memory sliding-window rate limiter (per client key, e.g. IP)."""

import threading
import time
from collections import deque


class RateLimiter:
    """Allow at most ``requests`` events per ``window_seconds`` per key.

    Thread-safe; old timestamps are pruned on every check so memory stays
    proportional to recent traffic.
    """

    def __init__(self, requests: int, window_seconds: int) -> None:
        if requests <= 0 or window_seconds <= 0:
            raise ValueError("requests and window_seconds must be positive")
        self._requests = requests
        self._window = float(window_seconds)
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Return ``True`` and record the event, or ``False`` if over limit."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                hits = deque()
                self._hits[key] = hits
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self._requests:
                return False
            hits.append(now)
            if len(self._hits) > 10_000:
                # Opportunistic purge of idle keys to bound memory.
                self._hits = {
                    k: v for k, v in self._hits.items() if v and v[-1] > cutoff
                }
            return True


#: Shared limiter guarding the expensive POST /api/v1/analyze endpoint:
#: 10 analyses per minute per client IP.
analyze_limiter = RateLimiter(requests=10, window_seconds=60)
