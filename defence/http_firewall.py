"""Network-level HTTP service firewall: iptables per-source throttling to a TCP dport (Linux, root).

Reduces **incoming PPS** to an application port (e.g. FastAPI) using ``hashlimit`` on
ESTABLISHED/RELATED traffic, plus optional caps on new TCP handshakes and parallel
connections. This is **not** a replacement for L7 (CAPTCHA); it is best-effort
**bandwidth / flood pressure** relief before packets reach the userspace server.

**Lab note:** If ``SNP_ASA`` (``defence.syn_defence``) is also used on the same port,
only the **first** matching ``INPUT`` rule for that dport is applied. Prefer one
defence for the same port, or re-order with ``iptables -I`` / turn one ``off`` first.

Enable (Linux + root)::

    sudo $(which python) -m defence.http_firewall on

Disable::

    sudo $(which python) -m defence.http_firewall off
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

_HTTP_FW_CHAIN = "SNP_HTTP"


def _is_linux() -> bool:
    return Path("/proc/sys/net/ipv4").is_dir()


def _require_linux() -> None:
    if not _is_linux():
        raise SystemExit("HTTP firewall rules require Linux with iptables (see /proc/sys/net/ipv4).")


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit(
            "This command must run as root, e.g.: "
            "sudo $(which python) -m defence.http_firewall on"
        )


def _delete_input_jump(port: int, chain: str = _HTTP_FW_CHAIN) -> None:
    while True:
        r = subprocess.run(
            [
                "iptables",
                "-C",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                chain,
            ],
            capture_output=True,
        )
        if r.returncode != 0:
            break
        subprocess.run(
            [
                "iptables",
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                chain,
            ],
            check=False,
        )


def _insert_input_jump(port: int, chain: str = _HTTP_FW_CHAIN, position: int = 1) -> None:
    """Insert INPUT jump near the top so earlier ACCEPT rules do not bypass it."""
    subprocess.run(
        [
            "iptables",
            "-I",
            "INPUT",
            str(position),
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-j",
            chain,
        ],
        check=True,
    )


def _hashlimit_name(port: int, suffix: str) -> str:
    base = f"hf{port}{suffix}"[:15]
    return base if len(base) <= 15 else base[:15]


def http_rules_on(
    port: int,
    established_pps: int = 200,
    new_syn_per_src: int = 20,
    max_conn_per_src: int = 0,
) -> None:
    """
    Install ``SNP_HTTP``: INVALID drop, per-source PPS on EST/REL, optional NEW-SYN
    hashlimit, optional parallel connection cap, else DROP.
    """
    _require_linux()
    _require_root()

    if established_pps < 1:
        raise SystemExit("established_pps must be >= 1 (or use off; 0 is invalid).")
    if new_syn_per_src < 1:
        raise SystemExit("new_syn_per_src must be >= 1.")

    _delete_input_jump(port, _HTTP_FW_CHAIN)
    subprocess.run(["iptables", "-F", _HTTP_FW_CHAIN], capture_output=True)
    subprocess.run(["iptables", "-X", _HTTP_FW_CHAIN], capture_output=True)
    subprocess.run(["iptables", "-N", _HTTP_FW_CHAIN], check=True)

    def _a(args: list[str]) -> None:
        subprocess.run(["iptables", *args], check=True)

    _a(["-A", _HTTP_FW_CHAIN, "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"])

    e_burst = max(established_pps * 2, 64)
    h_est = _hashlimit_name(port, "E")
    hlim_e = [
        "-A",
        _HTTP_FW_CHAIN,
        "-p",
        "tcp",
        "--dport",
        str(port),
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-m",
        "hashlimit",
        "--hashlimit-upto",
        f"{int(established_pps)}/second",
        "--hashlimit-burst",
        str(e_burst),
        "--hashlimit-mode",
        "srcip",
        "--hashlimit-name",
        h_est,
        "-j",
        "ACCEPT",
    ]
    r_e = subprocess.run(["iptables", *hlim_e], capture_output=True)
    if r_e.returncode != 0:
        print(
            "ERROR: hashlimit (xt_hashlimit) required for this firewall. "
            "Install/enable the module, or use defence.syn_defence for SYN-only lab.",
            flush=True,
        )
        subprocess.run(["iptables", "-F", _HTTP_FW_CHAIN], capture_output=True)
        subprocess.run(["iptables", "-X", _HTTP_FW_CHAIN], capture_output=True)
        raise SystemExit(1)

    _a(
        [
            "-A",
            _HTTP_FW_CHAIN,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "DROP",
        ]
    )

    if max_conn_per_src and max_conn_per_src > 0:
        conn = [
            "-A",
            _HTTP_FW_CHAIN,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-m",
            "tcp",
            "--syn",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-m",
            "connlimit",
            "--connlimit-above",
            str(int(max_conn_per_src)),
            "--connlimit-mask",
            "32",
            "-j",
            "DROP",
        ]
        cr = subprocess.run(["iptables", *conn], capture_output=True)
        if cr.returncode != 0:
            print(
                "WARN: connlimit match unavailable; parallel connection cap skipped.",
                flush=True,
            )

    h_new = _hashlimit_name(port, "N")
    n_burst = max(new_syn_per_src * 2, 16)
    hlim_n = [
        "-A",
        _HTTP_FW_CHAIN,
        "-p",
        "tcp",
        "--dport",
        str(port),
        "-m",
        "tcp",
        "--syn",
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-m",
        "hashlimit",
        "--hashlimit-upto",
        f"{int(new_syn_per_src)}/second",
        "--hashlimit-burst",
        str(n_burst),
        "--hashlimit-mode",
        "srcip",
        "--hashlimit-name",
        h_new,
        "-j",
        "ACCEPT",
    ]
    r_n = subprocess.run(["iptables", *hlim_n], capture_output=True)
    if r_n.returncode != 0:
        print(
            "WARN: per-source hashlimit on NEW failed; using global 'limit' for NEW SYNs.",
            flush=True,
        )
        _a(
            [
                "-A",
                _HTTP_FW_CHAIN,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-m",
                "tcp",
                "--syn",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW",
                "-m",
                "limit",
                "--limit",
                f"{max(1, new_syn_per_src)}/second",
                "--limit-burst",
                str(max(n_burst // 2, 8)),
                "-j",
                "ACCEPT",
            ],
        )
    _a(
        [
            "-A",
            _HTTP_FW_CHAIN,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-m",
            "tcp",
            "--syn",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-j",
            "DROP",
        ]
    )
    _a(["-A", _HTTP_FW_CHAIN, "-j", "DROP"])
    _insert_input_jump(port, _HTTP_FW_CHAIN, position=1)
    print(
        f"HTTP firewall ON: chain={_HTTP_FW_CHAIN} dport={port}; "
        f"~{established_pps} EST/REL pkt/s per source (burst~{e_burst}); "
        f"~{new_syn_per_src} NEW SYN/s per source; "
        f"max_conn_per_src={max_conn_per_src or 'off'}.",
        flush=True,
    )
    _warn_if_asa_also_in_input(port)


def _warn_if_asa_also_in_input(port: int) -> None:
    r = subprocess.run(["iptables", "-S", "INPUT"], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout:
        return
    if "SNP_ASA" in r.stdout and f"--dport {port}" in r.stdout:
        print(
            "NOTE: Both SNP_ASA and SNP_HTTP target this port. Only the **first** matching "
            "INPUT rule wins — verify `iptables -S INPUT` order or turn one defence off.",
            flush=True,
        )


def http_rules_off(port: int) -> None:
    _require_linux()
    _require_root()
    _delete_input_jump(port, _HTTP_FW_CHAIN)
    subprocess.run(["iptables", "-F", _HTTP_FW_CHAIN], capture_output=True)
    subprocess.run(["iptables", "-X", _HTTP_FW_CHAIN], capture_output=True)
    print(
        f"HTTP firewall OFF: chain={_HTTP_FW_CHAIN} removed for dport={port}.",
        flush=True,
    )


def http_firewall_status(port: int = 8000) -> dict[str, object]:
    """
    Introspect whether ``SNP_HTTP`` is present (read-only; may require CAP_NET_ADMIN
    to list rules on some systems).
    """
    if not _is_linux():
        return {
            "platform": "non-linux",
            "chain": _HTTP_FW_CHAIN,
            "active": None,
            "message": "iptables not applicable",
        }
    r = subprocess.run(
        ["iptables", "-S", _HTTP_FW_CHAIN], capture_output=True, text=True
    )
    if r.returncode != 0:
        return {
            "platform": "linux",
            "chain": _HTTP_FW_CHAIN,
            "port": port,
            "active": False,
            "input_jump_to_chain": False,
            "iptables_error": (r.stderr or "").strip() or "chain missing",
        }
    r_in = subprocess.run(["iptables", "-S", "INPUT"], capture_output=True, text=True)
    jump = False
    first_dport_rule: str | None = None
    first_dport_targets_http_chain = False
    if r_in.stdout and _HTTP_FW_CHAIN in r_in.stdout:
        for line in r_in.stdout.splitlines():
            if f"--dport {port}" not in line:
                continue
            if first_dport_rule is None:
                first_dport_rule = line
                first_dport_targets_http_chain = _HTTP_FW_CHAIN in line
            if _HTTP_FW_CHAIN in line:
                jump = True
    if first_dport_rule is None and r_in.stdout:
        for line in r_in.stdout.splitlines():
            if _HTTP_FW_CHAIN in line and f"--dport {port}" in line:
                first_dport_rule = line
                first_dport_targets_http_chain = True
                break
    out = (r.stdout or "").strip()
    return {
        "platform": "linux",
        "chain": _HTTP_FW_CHAIN,
        "port": port,
        "active": bool(jump) and out != "",
        "input_jump_to_chain": jump,
        "first_input_rule_for_port": first_dport_rule,
        "first_input_rule_hits_http_chain": first_dport_targets_http_chain,
        "chain_rules": out or None,
    }


def _cli() -> None:
    p = argparse.ArgumentParser(
        description="Network-level iptables firewall for a TCP (HTTP) service port."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_on = sub.add_parser("on", help="Enable SNP_HTTP throttling (needs root).")
    p_on.add_argument("--port", type=int, default=8000)
    p_on.add_argument(
        "--est-pps",
        type=int,
        default=200,
        help="Per-source ESTABLISHED/RELATED packets/s to dport (default 200).",
    )
    p_on.add_argument(
        "--new-syn",
        type=int,
        default=20,
        help="Per-source new SYNs/s to dport (default 20).",
    )
    p_on.add_argument(
        "--max-conn",
        type=int,
        default=0,
        help="Drop NEW SYNs if this source has more than N parallel conns to dport (0=off).",
    )

    p_off = sub.add_parser("off", help="Remove SNP_HTTP (needs root).")
    p_off.add_argument("--port", type=int, default=8000)

    p_st = sub.add_parser("status", help="Show whether SNP_HTTP is on (no root usually ok).")
    p_st.add_argument("--port", type=int, default=8000, help="Port to check in INPUT (default 8000).")

    args = p.parse_args()
    if args.cmd == "on":
        http_rules_on(
            args.port,
            established_pps=args.est_pps,
            new_syn_per_src=args.new_syn,
            max_conn_per_src=args.max_conn,
        )
    elif args.cmd == "off":
        http_rules_off(args.port)
    else:
        import json

        print(json.dumps(http_firewall_status(args.port), indent=2), flush=True)


if __name__ == "__main__":
    _cli()
