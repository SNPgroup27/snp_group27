"""In-process request metrics for demo."""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque


@dataclass
class ServerMetrics:
    request_count: int = 0
    error_count: int = 0
    appointment_posts: int = 0
    _latencies_ms: Deque[float] = field(default_factory=lambda: deque(maxlen=2000))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_request(self, latency_ms: float, is_error: bool) -> None:
        with self._lock:
            self.request_count += 1
            if is_error:
                self.error_count += 1
            self._latencies_ms.append(latency_ms)

    def record_appointment_post(self) -> None:
        with self._lock:
            self.appointment_posts += 1

    def snapshot(self) -> dict:
        with self._lock:
            lat = list(self._latencies_ms)
            req = self.request_count
            err = self.error_count
            posts = self.appointment_posts

        lat_sorted = sorted(lat)
        n = len(lat_sorted)

        def pct(p: float) -> float | None:
            if n == 0:
                return None
            idx = min(n - 1, max(0, int(p * n)))
            return round(lat_sorted[idx], 3)

        return {
            "uptime_s": _uptime_s(),
            "request_count": req,
            "error_count": err,
            "appointment_posts": posts,
            "latency_ms": {
                "p50": pct(0.50),
                "p95": pct(0.95),
                "p99": pct(0.99),
                "max": round(max(lat), 3) if lat else None,
            },
        }


_START_MONO = time.monotonic()


def _uptime_s() -> float:
    return round(time.monotonic() - _START_MONO, 3)


METRICS = ServerMetrics()
