"""Lightweight math CAPTCHA for POST /api/appointments (proof-of-concept, lab only)."""

from __future__ import annotations

import re
import secrets
import time

_CHALLENGES: dict[str, tuple[int, int, float]] = {}
_TTL_S = 300.0
_MAX_CHALLENGES = 5000


def _cleanup() -> None:
    now = time.time()
    for cid in [k for k, (_, _, exp) in _CHALLENGES.items() if exp < now]:
        del _CHALLENGES[cid]
    if len(_CHALLENGES) <= _MAX_CHALLENGES:
        return
    # Drop arbitrary oldest entries if unbounded growth (should not happen in normal use).
    for cid in list(_CHALLENGES.keys())[: len(_CHALLENGES) // 2]:
        del _CHALLENGES[cid]


def create_challenge() -> dict[str, str]:
    """Issue a one-time numeric challenge. Returns challenge_id and human-readable question."""
    _cleanup()
    a = secrets.randbelow(10) + 1
    b = secrets.randbelow(10) + 1
    cid = secrets.token_urlsafe(16)
    _CHALLENGES[cid] = (a, b, time.time() + _TTL_S)
    return {
        "challenge_id": cid,
        "question": f"What is {a} + {b}?",
    }


def verify_challenge(challenge_id: str, answer_str: str | None) -> bool:
    """Validate answer; consumes the challenge (single use)."""
    _cleanup()
    if not challenge_id or answer_str is None:
        return False
    entry = _CHALLENGES.pop(challenge_id, None)
    if entry is None:
        return False
    a, b, exp = entry
    if time.time() > exp:
        return False
    try:
        ans = int(str(answer_str).strip())
    except ValueError:
        return False
    return ans == a + b


QUESTION_RE = re.compile(r"What is (\d+) \+ (\d+)\?")


def parse_answer_from_question(question: str) -> int | None:
    """Helper for automated clients (e.g. IoMT sim): derive sum from question text."""
    m = QUESTION_RE.match(question.strip())
    if not m:
        return None
    return int(m.group(1)) + int(m.group(2))
