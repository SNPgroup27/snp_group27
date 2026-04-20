"""Read Linux kernel SYN-cookie state. SYN cookies are not implemented in Python — the OS applies them."""

from __future__ import annotations

from pathlib import Path

_PROC_SYN_COOKIES = Path("/proc/sys/net/ipv4/tcp_syncookies")


def read_tcp_syncookies() -> int | None:
    if not _PROC_SYN_COOKIES.is_file():
        return None
    try:
        return int(_PROC_SYN_COOKIES.read_text().strip())
    except (OSError, ValueError):
        return None


def syn_cookies_kernel_status() -> dict[str, object]:
    """
    Human-readable status for reports and GET /api/defence/syn-cookies.

    Values (Linux):
      0 — disabled 
      1 — enabled when backlog would overflow 
      2 — always enabled
    """
    val = read_tcp_syncookies()
    if val is None:
        return {
            "platform": "non_linux_or_unavailable",
            "tcp_syncookies": None,
            "syn_cookie_defence": None,
            "detail": (
                "SYN cookies are a Linux kernel control. "
                "This host has no /proc/sys/net/ipv4/tcp_syncookies — run the server on "
                "your Linux lab VM and use: sudo ./defence/syn_cookies.sh on"
            ),
        }

    meanings = {
        0: "disabled — SYN backlog can fill under flood",
        1: "enabled when needed — kernel encodes state in SYN-ACK ",
        2: "always enabled — SYN cookies always on",
    }
    return {
        "platform": "linux",
        "tcp_syncookies": val,
        "meaning": meanings.get(val, str(val)),
        "syn_cookie_defence_active": val != 0,
        "note": (
            "Defence is not in this Python app; uvicorn only receives connections the kernel "
            "has already accepted after the 3-way handshake. Enable with: "
            "sudo sysctl -w net.ipv4.tcp_syncookies=1"
        ),
    }
