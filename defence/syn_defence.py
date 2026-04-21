"""SYN-flood defence helpers (Linux kernel + complementary ingress filtering guidance)."""

from __future__ import annotations

from pathlib import Path

_PROC_SYN_COOKIES = Path("/proc/sys/net/ipv4/tcp_syncookies")
_PROC_RP_FILTER_ALL = Path("/proc/sys/net/ipv4/conf/all/rp_filter")
_PROC_RP_FILTER_DEFAULT = Path("/proc/sys/net/ipv4/conf/default/rp_filter")


def _read_int(path: Path) -> int | None:
    if not path.is_file():
        return None
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def read_tcp_syncookies() -> int | None:
    """Return Linux tcp_syncookies value, or None if unavailable."""
    return _read_int(_PROC_SYN_COOKIES)


def read_rp_filter() -> dict[str, int | None]:
    """
    Return reverse-path filtering values (ingress anti-spoofing hint).

    Linux rp_filter values:
      0 - disabled
      1 - strict mode
      2 - loose mode
    """
    return {
        "all": _read_int(_PROC_RP_FILTER_ALL),
        "default": _read_int(_PROC_RP_FILTER_DEFAULT),
    }


def ingress_filtering_guidance() -> dict[str, object]:
    """
    Complementary ingress-filtering guidance for coursework.

    Real ingress filtering is typically done at ISP/edge routers; on a host, rp_filter
    is the closest anti-spoofing control.
    """
    rp = read_rp_filter()
    all_v = rp["all"]
    default_v = rp["default"]
    active = (all_v in (1, 2)) or (default_v in (1, 2))
    return {
        "ingress_filtering_host_hint_active": active,
        "rp_filter": rp,
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
    """Human-readable status for GET /api/defence/syn-cookies."""
    val = read_tcp_syncookies()
    ingress = ingress_filtering_guidance()
    if val is None:
        return {
            "platform": "non_linux_or_unavailable",
            "tcp_syncookies": None,
            "syn_cookie_defence": None,
            "ingress_filtering": ingress,
            "detail": (
                "SYN cookies are a Linux kernel control. "
                "This host has no /proc/sys/net/ipv4/tcp_syncookies — run the server on "
                "your Linux lab VM and use: sudo ./defence/syn_cookies.sh on"
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
        "note": (
            "Defence is not in this Python app; uvicorn only receives connections the kernel "
            "has already accepted after the 3-way handshake. Enable with: "
            "sudo sysctl -w net.ipv4.tcp_syncookies=1"
        ),
    }
