"""SYN-flood defence: ASA iptables lab sim, SYN cookies, kernel profile, /proc monitors.

Quick lab (Linux, repo root, conda on): ``sudo $(which python) -m defence.syn_defence on``,
``off``, ``counts``. Same as ``asa-on`` / ``asa-off`` / ``asa-counters``.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

_PROC_SYN_COOKIES = Path("/proc/sys/net/ipv4/tcp_syncookies")
_PROC_RP_FILTER_ALL = Path("/proc/sys/net/ipv4/conf/all/rp_filter")
_PROC_RP_FILTER_DEFAULT = Path("/proc/sys/net/ipv4/conf/default/rp_filter")
_PROC_TCP_MAX_SYN_BACKLOG = Path("/proc/sys/net/ipv4/tcp_max_syn_backlog")
_PROC_TCP_SYNACK_RETRIES = Path("/proc/sys/net/ipv4/tcp_synack_retries")
_PROC_SOMAXCONN = Path("/proc/sys/net/core/somaxconn")
_PROC_TCP = Path("/proc/net/tcp")
_PROC_TCP6 = Path("/proc/net/tcp6")
_PROC_NETSTAT = Path("/proc/net/netstat")
_SYN_RECV_STATE = "03"  # TCP_SYN_RECV in /proc/net/tcp st field


def _local_port_hex_matches(local_addr: str, port_hex: str) -> bool:
    """Match local_address field from /proc/net/tcp{,6} (e.g. 0100007F:1F40)."""
    if ":" not in local_addr:
        return False
    lp = local_addr.rsplit(":", 1)[1].upper()
    return lp == port_hex.upper()

# Matches kernel-on profile in this module
RECOMMENDED_PROFILE: dict[str, int] = {
    "tcp_syncookies": 1,
    "tcp_max_syn_backlog": 4096,
    "tcp_synack_retries": 2,
    "somaxconn": 4096,
    "rp_filter_all": 1,
    "rp_filter_default": 1,
}


def _read_int(path: Path) -> int | None:
    if not path.is_file():
        return None
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def read_kernel_syn_tuning() -> dict[str, int | None]:
    """Single consolidated read of SYN-related kernel knobs + rp_filter."""
    return {
        "tcp_syncookies": _read_int(_PROC_SYN_COOKIES),
        "tcp_max_syn_backlog": _read_int(_PROC_TCP_MAX_SYN_BACKLOG),
        "tcp_synack_retries": _read_int(_PROC_TCP_SYNACK_RETRIES),
        "somaxconn": _read_int(_PROC_SOMAXCONN),
        "rp_filter_all": _read_int(_PROC_RP_FILTER_ALL),
        "rp_filter_default": _read_int(_PROC_RP_FILTER_DEFAULT),
    }


def read_rp_filter() -> dict[str, int | None]:
    """Reverse-path filter (subset of read_kernel_syn_tuning)."""
    k = read_kernel_syn_tuning()
    return {"all": k.get("rp_filter_all"), "default": k.get("rp_filter_default")}


def read_tcp_syncookies() -> int | None:
    return _read_int(_PROC_SYN_COOKIES)


def check_profile_compliance() -> dict[str, object]:
    """
    Compare live kernel values to RECOMMENDED_PROFILE.
    tcp_syncookies: compliant if non-zero (1 or 2 both OK).
    tcp_synack_retries: compliant if <= recommended (2).
    Others: compliant if >= recommended.
    """
    k = read_kernel_syn_tuning()
    if k.get("tcp_syncookies") is None:
        return {
            "profile_compliant": None,
            "checks": {},
            "reason": "not_linux_or_unavailable",
        }

    checks: dict[str, bool] = {}
    r = RECOMMENDED_PROFILE

    tc = k["tcp_syncookies"] or 0
    checks["tcp_syncookies_nonzero"] = tc != 0

    tmb = k["tcp_max_syn_backlog"] or 0
    checks["tcp_max_syn_backlog"] = tmb >= r["tcp_max_syn_backlog"]

    tsr = k["tcp_synack_retries"] if k["tcp_synack_retries"] is not None else 99
    checks["tcp_synack_retries"] = tsr <= r["tcp_synack_retries"]

    sm = k["somaxconn"] or 0
    checks["somaxconn"] = sm >= r["somaxconn"]

    rp_a = k["rp_filter_all"] or 0
    rp_d = k["rp_filter_default"] or 0
    checks["rp_filter_all"] = rp_a >= r["rp_filter_all"]
    checks["rp_filter_default"] = rp_d >= r["rp_filter_default"]

    overall = all(checks.values())
    return {
        "profile_compliant": overall,
        "checks": checks,
        "kernel_tuning": k,
        "recommended_profile": dict(r),
    }


def read_tcp_ext_counters() -> dict[str, int] | None:
    """
    Parse TcpExt: counters from /proc/net/netstat (SyncookiesSent, etc.).
    Returns None if unavailable.
    """
    if not _PROC_NETSTAT.is_file():
        return None
    try:
        lines = _PROC_NETSTAT.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    header: list[str] | None = None
    for line in lines:
        if not line.startswith("TcpExt:"):
            continue
        fields = line.split()
        if header is None:
            header = fields[1:]
            continue
        values = fields[1:]
        if len(values) != len(header):
            return None
        return dict(zip(header, (int(v) for v in values)))
    return None


def read_syn_recv_count(port: int | None = None) -> int | None:
    """
    Count half-open TCP connections in SYN-RECV state from /proc/net/tcp{,6}.
    State code for SYN-RECV is '03'.
    """
    if not _PROC_TCP.exists() and not _PROC_TCP6.exists():
        return None

    port_hex = f"{port:04X}" if port is not None else None
    total = 0
    for path in (_PROC_TCP, _PROC_TCP6):
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for row in lines[1:]:
            parts = row.split()
            if len(parts) <= 3 or parts[3] != _SYN_RECV_STATE:
                continue
            if port_hex is not None and not _local_port_hex_matches(parts[1], port_hex):
                continue
            total += 1
    return total


def monitor_syn_recv(
    interval: float = 1.0, duration: float = 30.0, port: int | None = None
) -> None:
    """Print SYN-RECV counts every `interval` seconds until `duration` elapses."""
    deadline = time.monotonic() + duration
    label = f" port={port}" if port is not None else " (all ports)"
    while time.monotonic() < deadline:
        c = read_syn_recv_count(port)
        print(f"SYN-RECV count{label}: {c}", flush=True)
        time.sleep(interval)


def print_half_open_once(port: int | None = None) -> None:
    """Print half-open (SYN-RECV) counts and syncookie TcpExt stats when available."""
    if not _PROC_TCP.exists() and not _PROC_TCP6.exists():
        print("Half-open TCP (SYN-RECV): unavailable (not Linux or no /proc/net/tcp)")
        return

    total = read_syn_recv_count(None)
    scoped = read_syn_recv_count(port) if port is not None else None
    tc = _read_int(_PROC_SYN_COOKIES)
    ext = read_tcp_ext_counters()

    if port is not None:
        print(f"SYN-RECV (half-open) on local port {port}: {scoped}")
    print(f"SYN-RECV (half-open) all local ports: {total}")
    if tc is not None:
        print(f"tcp_syncookies: {tc} (non-zero = kernel may use SYN cookies; SYN-RECV can stay low)")
    if ext:
        for key in ("SyncookiesSent", "SyncookiesRecv", "SyncookiesFailed"):
            if key in ext:
                print(f"{key}: {ext[key]}")
    if tc not in (None, 0) and (total == 0 or (scoped == 0 and port is not None)):
        print(
            "Hint: With SYN cookies on, backlog SYN-RECV often stays small; "
            "SyncookiesSent/Recv show defence activity. For a rising SYN-RECV demo, "
            "temporarily: sudo sysctl -w net.ipv4.tcp_syncookies=0 (lab only)."
        )


def ingress_filtering_guidance() -> dict[str, object]:
    rp_dict = read_rp_filter()
    all_v = rp_dict["all"]
    default_v = rp_dict["default"]
    active = (all_v in (1, 2)) or (default_v in (1, 2))
    return {
        "ingress_filtering_host_hint_active": active,
        "rp_filter": rp_dict,
        "meaning": {
            "0": "disabled",
            "1": "strict (strong anti-spoofing on host)",
            "2": "loose (basic anti-spoofing checks)",
        },
        "enable_example": [
            "sudo sysctl -w net.ipv4.conf.all.rp_filter=1",
            "sudo sysctl -w net.ipv4.conf.default.rp_filter=1",
        ],
        "note": (
            "For large-scale spoofed SYN floods, strongest ingress filtering is at ISP/edge. "
            "Host rp_filter is complementary defence."
        ),
    }


def syn_cookies_kernel_status() -> dict[str, object]:
    knobs = read_kernel_syn_tuning()
    val = knobs["tcp_syncookies"]
    ingress = ingress_filtering_guidance()
    syn_recv = read_syn_recv_count()
    syn_recv_port = read_syn_recv_count(8000)
    syncookie_ext = read_tcp_ext_counters()
    syncookie_subset: dict[str, int | None] = {}
    if syncookie_ext:
        for key in ("SyncookiesSent", "SyncookiesRecv", "SyncookiesFailed"):
            syncookie_subset[key] = syncookie_ext.get(key)
    else:
        syncookie_subset = {}
    compliance = check_profile_compliance()

    if val is None:
        return {
            "platform": "non_linux_or_unavailable",
            "tcp_syncookies": None,
            "syn_cookie_defence": None,
            "ingress_filtering": ingress,
            "kernel_tuning": knobs,
            "syn_recv_count": syn_recv,
            "syn_recv_port_8000": syn_recv_port,
            "tcp_ext_syncookies": syncookie_subset or None,
            "profile_compliance": compliance,
            "detail": (
                "SYN cookies are a Linux kernel control. "
                "This host has no /proc/sys/net/ipv4/tcp_syncookies"
            ),
        }

    meanings = {
        0: "disabled — SYN backlog can fill under flood",
        1: "enabled when needed — kernel encodes state in SYN-ACK",
        2: "always enabled — SYN cookies always on",
    }
    return {
        "platform": "linux",
        "tcp_syncookies": val,
        "meaning": meanings.get(val, str(val)),
        "syn_cookie_defence_active": val != 0,
        "ingress_filtering": ingress,
        "kernel_tuning": knobs,
        "syn_recv_count": syn_recv,
        "syn_recv_port_8000": syn_recv_port,
        "tcp_ext_syncookies": syncookie_subset or None,
        "recommended_profile": dict(RECOMMENDED_PROFILE),
        "profile_compliance": compliance,
        "note": (
            "Defence is kernel-enforced, not Python packet interception. "
            "Apply ASA + cookies: sudo $(which python) -m defence.syn_defence on ; "
            "kernel-only: sudo $(which python) -m defence.syn_defence kernel-on"
        ),
    }


# ---------------------------------------------------------------------------
# ASA lab (iptables) + kernel sysctl — requires Linux + root for apply commands
# ---------------------------------------------------------------------------

_ASA_CHAIN = "SNP_ASA"
_TRUSTED_RECENT = "SNP_TRUSTED"
_SYNPROXY_OPTS = [
    "--sack-perm",
    "--timestamp",
    "--mss",
    "1460",
    "--wscale",
    "7",
    "--ecn",
]
_PERSIST_SYSCTL = Path("/etc/sysctl.d/99-syn-defence.conf")


def _require_linux_iptables() -> None:
    if not Path("/proc/sys/net/ipv4/tcp_syncookies").is_file():
        raise SystemExit("SYN ASA / kernel controls require Linux with /proc/sys/net/ipv4.")


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit(
            "This command must run as root, e.g.: "
            "sudo $(which python) -m defence.syn_defence on"
        )


def _sysctl_w(key: str, value: str) -> None:
    subprocess.run(["sysctl", "-w", f"{key}={value}"], check=False, capture_output=True)


def _iptables_delete_jump(port: int, chain: str = _ASA_CHAIN) -> None:
    while True:
        r = subprocess.run(
            ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", chain],
            capture_output=True,
        )
        if r.returncode != 0:
            break
        subprocess.run(
            ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", chain],
            check=False,
        )


def _iptables_delete_synproxy(port: int) -> None:
    base = [
        "iptables",
        "-t",
        "raw",
        "-D",
        "PREROUTING",
        "-p",
        "tcp",
        "--dport",
        str(port),
        "-m",
        "tcp",
        "--syn",
        "-j",
        "SYNPROXY",
        *_SYNPROXY_OPTS,
    ]
    while subprocess.run(base, capture_output=True).returncode == 0:
        pass


def asa_syn_cookies_enable() -> None:
    _sysctl_w("net.ipv4.tcp_syncookies", "1")


def asa_rules_on(
    port: int, threshold: int, intercept: bool, established_pps: int = 100
) -> None:
    """
    iptables SNP_ASA (lab model of stateful ASA + SYN cookies):

    - INVALID: drop garbage.
    - ESTABLISHED,RELATED: per-source *packet* cap (``established_pps``) to this dport, then mark
      trusted; excess dropped so HTTP floods after the TCP handshake are throttled, not just SYNs.
    - trusted-source cache (xt_recent): any source seen in ESTABLISHED flow is cached for 10m;
      NEW SYN from trusted source is allowed before flood caps.
    - NEW + connlimit: drop when the same source IP has **more than** `threshold` parallel tracked
      TCP flows to this port (allows up to `threshold`; spoofed RandIP spreads across many IPs).
    - NEW + limit: globally ~`threshold` brand-new SYNs/s to this port (burst = threshold);
      excess SYNs dropped before the backlog fills.
    - tcp_syncookies=1: kernel encodes state in SYN-ACK so incomplete handshakes cost less backlog.

    If ``established_pps`` is 0, legacy behaviour: accept all EST/REL to this dport (SYN-only
    throttling, higher server load on established HTTP abuse).

    Wireshark row colours (red/grey) are decided by Wireshark heuristics, not by this script.
    """
    _require_linux_iptables()
    _require_root()
    chain = _ASA_CHAIN
    asa_syn_cookies_enable()
    _iptables_delete_jump(port, chain)
    _iptables_delete_synproxy(port)
    subprocess.run(["iptables", "-F", chain], capture_output=True)
    subprocess.run(["iptables", "-X", chain], capture_output=True)
    subprocess.run(["iptables", "-N", chain], check=True)

    def _a(args: list[str]) -> None:
        subprocess.run(["iptables", *args], check=True)

    _a(["-A", chain, "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"])
    # Mark source IPs that have traffic in an established flow as "trusted" for short time.
    _a(
        [
            "-A",
            chain,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-m",
            "recent",
            "--set",
            "--name",
            _TRUSTED_RECENT,
        ]
    )
    if established_pps and established_pps > 0:
        burst = max(int(established_pps) * 2, 32)
        hl = f"snpP{port}"[:15]  # hashlimit name max 15 chars
        hlim = [
            "-A",
            chain,
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
            str(burst),
            "--hashlimit-mode",
            "srcip",
            "--hashlimit-name",
            hl,
            "-j",
            "ACCEPT",
        ]
        h_ok = subprocess.run(["iptables", *hlim], capture_output=True)
        if h_ok.returncode == 0:
            _a(
                [
                    "-A",
                    chain,
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
        else:
            print(
                "WARN: iptables hashlimit not available; EST/REL pps to this port not throttled. "
                "Install xt_hashlimit (kernel module) or set --est-pps 0 for legacy all-ACCEPT.",
                flush=True,
            )
            _a(
                [
                    "-A",
                    chain,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ]
            )
    else:
        _a(
            [
                "-A",
                chain,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
    # If a source completed handshake recently, allow future NEW SYN from that source quickly.
    _a(
        [
            "-A",
            chain,
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
            "recent",
            "--rcheck",
            "--seconds",
            "600",
            "--name",
            _TRUSTED_RECENT,
            "-j",
            "ACCEPT",
        ]
    )
    # Per-source parallel connection cap (same threshold value as SYN/s for lab simplicity)
    connlim = [
        "-A",
        chain,
        "-p",
        "tcp",
        "--dport",
        str(port),
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-m",
        "connlimit",
        "--connlimit-above",
        str(threshold),
        "--connlimit-mask",
        "32",
        "-j",
        "DROP",
    ]
    rlim = subprocess.run(["iptables", *connlim], capture_output=True)
    if rlim.returncode != 0:
        print(
            "WARN: iptables connlimit match unavailable (kernel/module); "
            "continuing with SYN/s rate limit + SYN cookies only.",
            flush=True,
        )
    _a(
        [
            "-A",
            chain,
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
            f"{threshold}/second",
            "--limit-burst",
            str(threshold),
            "-j",
            "ACCEPT",
        ]
    )
    _a(
        [
            "-A",
            chain,
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
    _a(["-A", chain, "-j", "RETURN"])
    _a(["-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", chain])
    est_str = f"per-src EST/REL pps<={established_pps} (+DROP excess) " if established_pps and established_pps > 0 else "EST/REL all ACCEPT (legacy) "
    print(
        f"ASA-sim ON: chain={chain} dport={port}; "
        f"{est_str}trusted-source; per-src NEW connlimit>{threshold} DROP; "
        f"~{threshold} NEW SYN/s global; tcp_syncookies=1.",
        flush=True,
    )
    if intercept:
        sp = [
            "iptables",
            "-t",
            "raw",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-m",
            "tcp",
            "--syn",
            "-j",
            "SYNPROXY",
            *_SYNPROXY_OPTS,
        ]
        r = subprocess.run(sp, capture_output=True)
        if r.returncode == 0:
            print(f"TCP intercept: SYNPROXY on raw PREROUTING dport={port}.", flush=True)
        else:
            print(
                "WARN: SYNPROXY target unavailable; SYN cookies + rate limit still active.",
                flush=True,
            )
    print(
        "Reminders:  off  = remove ASA rules  |  counts  = half-open + short stats  |  "
        "counts --verbose  = full iptables tables",
        flush=True,
    )


def _parse_asa_new_syn_packet_counts(
    port: int, iptables_list_stdout: str
) -> tuple[int, int, int, int]:
    """
    Return:
      (pkts_new_syn_under_shaper, pkts_new_syn_drop_excess, pkts_connlimit_drop, pkts_trusted_accept)
    from `iptables -L SNP_ASA -v -n -x` text.
    """
    allowed = dropped = connlim = trusted = 0
    dpt = f"dpt:{port}"
    for line in iptables_list_stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Chain ") or stripped.startswith("pkts "):
            continue
        parts = stripped.split()
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        pkts = int(parts[0])
        if dpt not in line:
            continue
        if "ctstate INVALID" in line:
            continue
        if "recent:" in line and _TRUSTED_RECENT in line and parts[2] == "ACCEPT":
            trusted = pkts
        elif "connlimit" in line and parts[2] == "DROP" and "NEW" in line:
            connlim = pkts
        elif "limit" in line and "NEW" in line and parts[2] == "ACCEPT":
            allowed = pkts
        elif parts[2] == "DROP" and "tcp" in line and "NEW" in line and "limit" not in line and "connlimit" not in line:
            dropped = pkts
    return allowed, dropped, connlim, trusted


def asa_print_counters_verbose(port: int) -> None:
    """Full iptables -v listing (legacy noisy view)."""
    print(f"=== INPUT rules touching dport {port} (pkts/bytes) ===", flush=True)
    r = subprocess.run(["iptables", "-L", "INPUT", "-v", "-n", "-x"], capture_output=True, text=True)
    if r.stdout:
        for line in r.stdout.splitlines():
            if f"dpt:{port}" in line or _ASA_CHAIN in line:
                print(line, flush=True)
    print(f"=== Chain {_ASA_CHAIN} (full) ===", flush=True)
    r2 = subprocess.run(
        ["iptables", "-L", _ASA_CHAIN, "-v", "-n", "-x"], capture_output=True, text=True
    )
    print(r2.stdout or "(chain missing — run: on or asa-on)", end="", flush=True)


def asa_print_counters(port: int, *, verbose: bool = False) -> None:
    """Human-readable snapshot: half-open sockets + ASA counters; use verbose for full iptables."""
    if not Path("/proc/sys/net/ipv4/tcp_syncookies").is_file():
        print("(not Linux — counters unavailable)", flush=True)
        return

    syn_port = read_syn_recv_count(port)
    syn_all = read_syn_recv_count(None)
    tc = _read_int(_PROC_SYN_COOKIES)
    print(f"Half-open (SYN-RECV) on port {port}: {syn_port}", flush=True)
    print(f"Half-open (SYN-RECV) all ports: {syn_all}", flush=True)
    if tc is not None:
        print(f"tcp_syncookies: {tc}", flush=True)
    ext = read_tcp_ext_counters()
    if ext:
        ss = ext.get("SyncookiesSent")
        sr = ext.get("SyncookiesRecv")
        if ss is not None or sr is not None:
            print(f"SyncookiesSent: {ss}  SyncookiesRecv: {sr}", flush=True)

    r2 = subprocess.run(
        ["iptables", "-L", _ASA_CHAIN, "-v", "-n", "-x"], capture_output=True, text=True
    )
    if not r2.stdout or "Chain" not in r2.stdout:
        print(f"(ASA chain missing — run: sudo $(which python) -m defence.syn_defence on)", flush=True)
    else:
        allowed, dropped, connlim, trusted = _parse_asa_new_syn_packet_counts(port, r2.stdout)
        print(
            f"ASA iptables: trusted-source NEW accepts: {trusted} pkts  |  "
            f"per-src connlimit drops: {connlim} pkts  |  "
            f"NEW SYNs accepted under global rate limit: {allowed} pkts  |  "
            f"NEW SYNs dropped (over global cap): {dropped} pkts",
            flush=True,
        )

    if verbose:
        print("", flush=True)
        asa_print_counters_verbose(port)


def asa_rules_off(port: int) -> None:
    _require_linux_iptables()
    _require_root()
    _iptables_delete_jump(port, _ASA_CHAIN)
    _iptables_delete_synproxy(port)
    subprocess.run(["iptables", "-F", _ASA_CHAIN], capture_output=True)
    subprocess.run(["iptables", "-X", _ASA_CHAIN], capture_output=True)
    print(
        "ASA-sim OFF (iptables removed). tcp_syncookies unchanged. "
        "Turn defence on again: sudo $(which python) -m defence.syn_defence on",
        flush=True,
    )
    print(
        "Optional — disable SYN cookies too: sudo $(which python) -m defence.syn_defence kernel-off",
        flush=True,
    )


def asa_print_status(port: int) -> None:
    if not Path("/proc/sys/net/ipv4/tcp_syncookies").is_file():
        print("(not Linux — iptables ASA sim unavailable)", flush=True)
        return
    print(f"=== INPUT (port {port} / {_ASA_CHAIN}) ===", flush=True)
    r = subprocess.run(["iptables", "-S", "INPUT"], capture_output=True, text=True)
    if r.stdout:
        for line in r.stdout.splitlines():
            if _ASA_CHAIN in line or f"--dport {port}" in line:
                print(line, flush=True)
    print(f"=== chain {_ASA_CHAIN} ===", flush=True)
    r2 = subprocess.run(["iptables", "-S", _ASA_CHAIN], capture_output=True, text=True)
    print(r2.stdout or "(missing)", end="", flush=True)
    print("=== raw PREROUTING (SYNPROXY) ===", flush=True)
    r3 = subprocess.run(
        ["iptables", "-t", "raw", "-S", "PREROUTING"], capture_output=True, text=True
    )
    if r3.stdout:
        for line in r3.stdout.splitlines():
            if "SYNPROXY" in line or str(port) in line:
                print(line, flush=True)
    subprocess.run(["sysctl", "net.ipv4.tcp_syncookies"], check=False)


def kernel_profile_on() -> None:
    """Full SYN-related sysctl profile (lab)."""
    _require_linux_iptables()
    _require_root()
    _sysctl_w("net.ipv4.tcp_syncookies", "1")
    _sysctl_w("net.ipv4.conf.all.rp_filter", "1")
    _sysctl_w("net.ipv4.conf.default.rp_filter", "1")
    _sysctl_w("net.ipv4.tcp_max_syn_backlog", "4096")
    _sysctl_w("net.ipv4.tcp_synack_retries", "2")
    _sysctl_w("net.core.somaxconn", "4096")
    print("Kernel SYN profile ON (sysctl).", flush=True)


def kernel_profile_off() -> None:
    _require_linux_iptables()
    _require_root()
    _sysctl_w("net.ipv4.tcp_syncookies", "0")
    _sysctl_w("net.ipv4.conf.all.rp_filter", "0")
    _sysctl_w("net.ipv4.conf.default.rp_filter", "0")
    _sysctl_w("net.ipv4.tcp_max_syn_backlog", "1024")
    _sysctl_w("net.ipv4.tcp_synack_retries", "5")
    _sysctl_w("net.core.somaxconn", "128")
    print("Kernel SYN profile OFF (lab defaults).", flush=True)


def kernel_profile_status() -> None:
    if not Path("/proc/sys/net/ipv4/tcp_syncookies").is_file():
        print("(not Linux — no IPv4 sysctl snapshot)", flush=True)
        return
    subprocess.run(["sysctl", "net.ipv4.tcp_syncookies"], check=False)
    subprocess.run(["sysctl", "net.ipv4.conf.all.rp_filter"], check=False)
    subprocess.run(["sysctl", "net.ipv4.conf.default.rp_filter"], check=False)
    subprocess.run(["sysctl", "net.ipv4.tcp_max_syn_backlog"], check=False)
    subprocess.run(["sysctl", "net.ipv4.tcp_synack_retries"], check=False)
    subprocess.run(["sysctl", "net.core.somaxconn"], check=False)


def persist_profile_on() -> None:
    _require_linux_iptables()
    _require_root()
    body = """net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.tcp_synack_retries=2
net.core.somaxconn=4096
"""
    _PERSIST_SYSCTL.write_text(body, encoding="utf-8")
    subprocess.run(["sysctl", "--system"], capture_output=True)
    print(f"Persisted profile to {_PERSIST_SYSCTL}", flush=True)


def persist_profile_off() -> None:
    _require_linux_iptables()
    _require_root()
    if _PERSIST_SYSCTL.is_file():
        _PERSIST_SYSCTL.unlink()
        subprocess.run(["sysctl", "--system"], capture_output=True)
        print(f"Removed {_PERSIST_SYSCTL}", flush=True)
    else:
        print(f"No file at {_PERSIST_SYSCTL}", flush=True)


def _cli() -> None:
    import argparse
    import json

    p = argparse.ArgumentParser(
        description=(
            "SYN defence: ASA-style iptables + SYN cookies. Shorthand (needs sudo): on | off | counts. "
            "Full names: asa-on, asa-off, asa-counters, …"
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_short_on = sub.add_parser("on", help="Turn ASA defence on (same as asa-on). Needs root.")
    p_short_on.add_argument("--port", type=int, default=8000)
    p_short_on.add_argument(
        "--threshold",
        type=int,
        default=5,
        metavar="N",
        help="Per-src connlimit + global NEW SYN/s (default 5).",
    )
    p_short_on.add_argument(
        "--est-pps",
        type=int,
        default=100,
        dest="est_pps",
        metavar="N",
        help="Per-source ESTABLISHED/RELATED packets/s to dport (0=unlimited, legacy; default 100).",
    )

    p_short_off = sub.add_parser("off", help="Turn ASA defence off (same as asa-off). Needs root.")
    p_short_off.add_argument("--port", type=int, default=8000)

    p_short_ct = sub.add_parser(
        "counts",
        help="Half-open SYN-RECV + short ASA stats (add --verbose for full iptables).",
    )
    p_short_ct.add_argument("--port", type=int, default=8000)
    p_short_ct.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Append full iptables -v listings.",
    )

    pm = sub.add_parser("monitor", help="Poll SYN-RECV count (half-open) from /proc/net/tcp.")
    pm.add_argument("--interval", type=float, default=1.0, help="Seconds between samples.")
    pm.add_argument("--duration", type=float, default=30.0, help="Total seconds to run.")
    pm.add_argument(
        "--port",
        type=int,
        default=None,
        help="Only count SYN-RECV on this local port (e.g. 8000 for uvicorn).",
    )

    sub.add_parser("compliance", help="Print profile compliance vs recommended kernel profile.")
    sub.add_parser("status", help="Print full status JSON (same shape as GET /api/defence/syn-cookies).")
    ph = sub.add_parser(
        "half-open",
        help="One-shot: SYN-RECV counts (+ TcpExt syncookie counters on Linux).",
    )
    ph.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Show SYN-RECV scoped to this local port (default 8000); use 0 for port column off.",
    )

    p_asa_on = sub.add_parser(
        "asa-on",
        help="Lab ASA sim: tcp_syncookies=1 + iptables chain (global NEW SYN/s to --port). Needs root.",
    )
    p_asa_on.add_argument("--port", type=int, default=8000)
    p_asa_on.add_argument(
        "--threshold",
        type=int,
        default=5,
        metavar="N",
        help="Per-src connlimit + global NEW SYN/s; burst = same (default 5).",
    )
    p_asa_on.add_argument(
        "--est-pps",
        type=int,
        default=100,
        dest="est_pps",
        metavar="N",
        help="Per-source EST/REL pps to dport (0=unlimited; default 100).",
    )

    p_asa_int = sub.add_parser(
        "asa-intercept",
        help="Same as asa-on plus SYNPROXY on raw PREROUTING if the kernel supports it.",
    )
    p_asa_int.add_argument("--port", type=int, default=8000)
    p_asa_int.add_argument("--threshold", type=int, default=5, metavar="N")
    p_asa_int.add_argument(
        "--est-pps",
        type=int,
        default=100,
        dest="est_pps",
        metavar="N",
        help="Per-source EST/REL pps to dport (0=unlimited; default 100).",
    )

    p_asa_off = sub.add_parser("asa-off", help="Remove ASA iptables chain and SYNPROXY rules. Needs root.")
    p_asa_off.add_argument("--port", type=int, default=8000)

    p_asa_st = sub.add_parser("asa-status", help="Print iptables rules + tcp_syncookies for the ASA chain.")
    p_asa_st.add_argument("--port", type=int, default=8000)

    p_asa_ct = sub.add_parser(
        "asa-counters",
        help="Half-open + short ASA stats (same as counts; --verbose for full tables).",
    )
    p_asa_ct.add_argument("--port", type=int, default=8000)
    p_asa_ct.add_argument("--verbose", "-v", action="store_true", help="Append full iptables -v listings.")

    sub.add_parser("kernel-on", help="Apply full SYN sysctl profile (no iptables). Needs root.")
    sub.add_parser("kernel-off", help="Revert lab sysctl profile. Needs root.")
    sub.add_parser("kernel-status", help="Print key sysctl values (no root).")
    sub.add_parser("persist-on", help=f"Write {_PERSIST_SYSCTL.name} and sysctl --system. Needs root.")
    sub.add_parser("persist-off", help=f"Remove {_PERSIST_SYSCTL.name} if present. Needs root.")

    args = p.parse_args()
    if args.cmd == "monitor":
        monitor_syn_recv(interval=args.interval, duration=args.duration, port=args.port)
    elif args.cmd == "compliance":
        print(json.dumps(check_profile_compliance(), indent=2))
    elif args.cmd == "status":
        print(json.dumps(syn_cookies_kernel_status(), indent=2))
    elif args.cmd == "half-open":
        port_filter = args.port if args.port != 0 else None
        print_half_open_once(port_filter)
    elif args.cmd in ("asa-on", "on"):
        asa_rules_on(
            args.port, args.threshold, intercept=False, established_pps=args.est_pps
        )
    elif args.cmd == "asa-intercept":
        asa_rules_on(
            args.port, args.threshold, intercept=True, established_pps=args.est_pps
        )
    elif args.cmd in ("asa-off", "off"):
        asa_rules_off(args.port)
    elif args.cmd == "asa-status":
        asa_print_status(args.port)
    elif args.cmd in ("asa-counters", "counts"):
        asa_print_counters(args.port, verbose=bool(getattr(args, "verbose", False)))
    elif args.cmd == "kernel-on":
        kernel_profile_on()
    elif args.cmd == "kernel-off":
        kernel_profile_off()
    elif args.cmd == "kernel-status":
        kernel_profile_status()
    elif args.cmd == "persist-on":
        persist_profile_on()
    elif args.cmd == "persist-off":
        persist_profile_off()


if __name__ == "__main__":
    _cli()
