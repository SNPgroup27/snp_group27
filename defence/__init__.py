"""Coursework defence helpers: CAPTCHA (application layer), SYN kernel helpers in defence.syn_defence."""

from defence.captcha import (
    captcha_enabled,
    create_challenge,
    set_captcha_enabled,
    verify_challenge,
)

__all__ = [
    "create_challenge",
    "verify_challenge",
    "captcha_enabled",
    "set_captcha_enabled",
]
