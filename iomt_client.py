#!/usr/bin/env python3
"""
Simulated IoMT device (CGM-style): posts telemetry to the datacenter on an interval.

"""

from __future__ import annotations

import argparse
import threading
import time
from dataclasses import dataclass, field

import httpx

from cgm_datastream import random_cgm_reading

DEFAULT_PATH = "/api/cgm/readings"


@dataclass
class WorkerStats:
    ok: int = 0
    fail: int = 0
    timeouts: int = 0
    last_error: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_ok(self) -> None:
        with self.lock:
            self.ok += 1

    def add_fail(self, msg: str, is_timeout: bool) -> None:
        with self.lock:
            self.fail += 1
            if is_timeout:
                self.timeouts += 1
            self.last_error = msg[:200]


def run_worker(
    wid: int,
    base_url: str,
    path: str,
    interval_s: float,
    timeout_s: float,
    stop: threading.Event,
    stats: WorkerStats,
    print_each: bool,
) -> None:
    device_id = f"sim-cgm-{wid}"
    url = base_url.rstrip("/") + path
    with httpx.Client(timeout=timeout_s) as client:
        while not stop.is_set():
            payload = random_cgm_reading(device_id)
            try:
                r = client.post(url, json=payload)
                if r.status_code < 400:
                    stats.add_ok()
                    if print_each:
                        g = payload["glucose_mg_dl"]
                        ts = payload.get("timestamp", "")
                        print(
                            f"[IoMT → datacenter] device={device_id} "
                            f"glucose_mg_dl={g} timestamp={ts}",
                            flush=True,
                        )
                else:
                    stats.add_fail(f"HTTP {r.status_code}: {r.text[:80]}", False)
                    if print_each:
                        print(f"[IoMT] POST failed: {r.status_code} {r.text[:120]}", flush=True)
            except httpx.TimeoutException as e:
                stats.add_fail(str(e), True)
                if print_each:
                    print(f"[IoMT] timeout: {e}", flush=True)
            except httpx.RequestError as e:
                stats.add_fail(str(e), False)
                if print_each:
                    print(f"[IoMT] request error: {e}", flush=True)
            stop.wait(interval_s)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Simulated CGM / IoMT telemetry client (terminal output; no browser needed)."
    )
    p.add_argument("--base-url", default="http://127.0.0.1:8000", help="Datacenter base URL")
    p.add_argument("--path", default=DEFAULT_PATH, help="CGM ingest path")
    p.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between posts per worker (default: slow pace for demos)",
    )
    p.add_argument("--workers", type=int, default=1, help="Parallel simulated devices")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout (seconds)")
    p.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds (0 = run until Ctrl+C)")
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-message lines (errors still print)",
    )
    args = p.parse_args()

    print_each = not args.quiet
    stop = threading.Event()
    stats = WorkerStats()
    threads = [
        threading.Thread(
            target=run_worker,
            args=(
                i,
                args.base_url,
                args.path,
                args.interval,
                args.timeout,
                stop,
                stats,
                print_each,
            ),
            daemon=True,
        )
        for i in range(args.workers)
    ]
    for t in threads:
        t.start()

    print(
        "Fake IoMT client running. Each line is one POST of fake CGM data to the server.",
        "Press Ctrl+C to stop.\n",
        flush=True,
    )

    start = time.monotonic()
    try:
        while True:
            time.sleep(0.5)
            elapsed = time.monotonic() - start
            if args.duration > 0 and elapsed >= args.duration:
                break
    except KeyboardInterrupt:
        print("\nStopping…", flush=True)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2.0)
        with stats.lock:
            ok, fail, to = stats.ok, stats.fail, stats.timeouts
            last = stats.last_error
        print(
            f"Summary: ok={ok} fail={fail} timeouts={to} last_err={last!r}",
            flush=True,
        )


if __name__ == "__main__":
    main()
