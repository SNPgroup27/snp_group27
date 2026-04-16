#!/usr/bin/env python3
"""
HTTP flood against the datacenter API.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

import httpx

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from appointments_datastream import next_appointment  


async def _worker(client: httpx.AsyncClient, url: str, deadline: float) -> tuple[int, int]:
    ok = err = 0
    while time.monotonic() < deadline:
        payload = next_appointment()
        try:
            r = await client.post(url, json=payload)
            if r.status_code < 400:
                ok += 1
            else:
                err += 1
        except httpx.HTTPError:
            err += 1
    return ok, err


def run_http_flood(base_url: str, path: str, concurrency: int, duration_s: float) -> None:
    url = base_url.rstrip("/") + path
    deadline = time.monotonic() + duration_s

    async def _run() -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            results = await asyncio.gather(
                *[_worker(client, url, deadline) for _ in range(concurrency)]
            )
        total_ok = sum(a for a, _ in results)
        total_err = sum(b for _, b in results)
        print(
            f"HTTP flood complete: ok={total_ok} err={total_err} "
            f"duration_s={duration_s} concurrency={concurrency}"
        )

    asyncio.run(_run())


def main() -> None:
    p = argparse.ArgumentParser(
        description="HTTP flood against the datacenter API."
    )
    p.add_argument(
        "--target",
        default="http://127.0.0.1:8000",
        help="Base URL of the datacenter API (default: http://127.0.0.1:8000)",
    )
    p.add_argument(
        "--path",
        default="/api/appointments",
        help="Path to flood (default: /api/appointments)",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=50,
        help="Number of concurrent workers (default: 50)",
    )
    p.add_argument(
        "--duration",
        type=float,
        default=20.0,
        help="How long to run the flood, in seconds (default: 20)",
    )
    args = p.parse_args()

    print(
        "Starting HTTP flood.",
        flush=True,
    )
    run_http_flood(args.target, args.path, args.concurrency, args.duration)


if __name__ == "__main__":
    main()

