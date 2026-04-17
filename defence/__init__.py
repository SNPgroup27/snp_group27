"""Coursework defence helpers: CAPTCHA (application layer), SYN cookie notes (kernel)."""

from defence.captcha import create_challenge, verify_challenge

__all__ = ["create_challenge", "verify_challenge"]
