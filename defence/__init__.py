"""Coursework defence helpers: CAPTCHA (application layer), SYN cookie notes (kernel)."""

from defence.captcha import (
    captcha_enabled,
    create_challenge,
    set_captcha_enabled,
    verify_challenge,
)
from defence.syn_cookies import read_tcp_syncookies, syn_cookies_kernel_status

__all__ = [
    "create_challenge",
    "verify_challenge",
    "captcha_enabled",
    "set_captcha_enabled",
    "read_tcp_syncookies",
    "syn_cookies_kernel_status",
]
