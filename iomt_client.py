#!/usr/bin/env python3
"""
Simulated IoMT device: replays hospital appointments to the datacenter API.

Each request is built from data/appointments.csv via appointments_datastream.py
and sent to POST /api/appointments on the server.
"""

from __future__ import annotations

import argparse
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from appointments_datastream import next_appointment

DEFAULT_PATH = "/api/appointments"


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
    use_captcha: bool,
    source_ip: str | None,
) -> None:
    device_label = f"sim-appointments-client-{wid}"
    url = base_url.rstrip("/") + path
    base = base_url.rstrip("/")
    transport = httpx.HTTPTransport(local_address=source_ip) if source_ip else httpx.HTTPTransport()
    with httpx.Client(timeout=timeout_s, transport=transport) as client:
        while not stop.is_set():
            payload = dict(next_appointment())
            if use_captcha:
                ch = client.get(f"{base}/api/captcha/challenge")
                if ch.status_code >= 400:
                    stats.add_fail(f"captcha challenge HTTP {ch.status_code}", False)
                    stop.wait(interval_s)
                    continue
                data = ch.json()
                cid = data.get("challenge_id")
                if cid is None:
                    stats.add_fail("captcha challenge parse failed", False)
                    stop.wait(interval_s)
                    continue
                payload["captcha_challenge_id"] = cid
                payload["captcha_answer"] = "checked"
            try:
                r = client.post(url, json=payload)
                if r.status_code < 400:
                    stats.add_ok()
                    if print_each:
                        appt_id = payload.get("appointment_id")
                        patient = payload.get("patient_id")
                        doctor = payload.get("doctor_id")
                        date = payload.get("appointment_date")
                        time_str = payload.get("appointment_time")
                        print(
                            "[Appointments → datacenter] "
                            f"client={device_label} appointment_id={appt_id} "
                            f"patient={patient} doctor={doctor} "
                            f"date={date} time={time_str}",
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
        description="Simulated IoMT appointments client (terminal output; no browser needed)."
    )
    p.add_argument("--base-url", default="http://127.0.0.1:8000", help="Datacenter base URL")
    p.add_argument("--path", default=DEFAULT_PATH, help="Appointments ingest path")
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
    p.add_argument(
        "--use-captcha",
        action="store_true",
        help="Fetch /api/captcha/challenge before each POST (server needs ENABLE_APPOINTMENT_CAPTCHA=1)",
    )
    p.add_argument(
        "--source-ip",
        default=None,
        help=(
            "Bind outgoing client connections to this local source IP "
            "(must exist on this host/interface). If omitted and base-url host is 127.0.0.1, "
            "client auto-binds to 127.0.0.2 for loopback demos."
        ),
    )
    args = p.parse_args()

    print_each = not args.quiet
    # Loopback lab convenience: keep destination on 127.0.0.1 while giving
    # the legit IoMT client a distinct source identity for firewall trust logic.
    parsed = urlparse(args.base_url)
    host = (parsed.hostname or "").strip()
    effective_source_ip = args.source_ip
    if effective_source_ip is None and host == "127.0.0.1":
        effective_source_ip = "127.0.0.2"

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
                args.use_captcha,
                effective_source_ip,
            ),
            daemon=True,
        )
        for i in range(args.workers)
    ]
    for t in threads:
        t.start()

    print(
        "Fake IoMT client running. Each line is one POST of an appointment to the server.",
        f"Source IP bind: {effective_source_ip or 'default route/interface'}. Press Ctrl+C to stop.\n",
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
