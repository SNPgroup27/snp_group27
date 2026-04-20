"""Lightweight checkbox-style CAPTCHA for POST /api/appointments.

Also provides a tiny CLI to toggle CAPTCHA state:

    python defence/captcha.py --on
    python defence/captcha.py --off
    python defence/captcha.py --status
"""

from __future__ import annotations

import argparse
import json
import secrets
import time
from pathlib import Path

_CHALLENGES: dict[str, float] = {}
_TTL_S = 300.0
_MAX_CHALLENGES = 5000
_STATE_FILE = Path(__file__).with_name(".captcha_state.json")
_RATE_WINDOW_S = 10.0
_RATE_LIMIT_MAX_REQUESTS = 30
_RATE_BUCKETS: dict[str, tuple[float, int]] = {}


def _cleanup() -> None:
    now = time.time()
    for cid in [k for k, exp in _CHALLENGES.items() if exp < now]:
        del _CHALLENGES[cid]
    if len(_CHALLENGES) <= _MAX_CHALLENGES:
        return
    # Drop arbitrary oldest entries if unbounded growth
    for cid in list(_CHALLENGES.keys())[: len(_CHALLENGES) // 2]:
        del _CHALLENGES[cid]

    # Also expire rate-limit buckets from old windows.
    for client_id in [k for k, (window_start, _) in _RATE_BUCKETS.items() if now - window_start > _RATE_WINDOW_S]:
        del _RATE_BUCKETS[client_id]


def create_challenge() -> dict[str, str]:
    """Issue a one-time checkbox challenge token."""
    _cleanup()
    cid = secrets.token_urlsafe(16)
    _CHALLENGES[cid] = time.time() + _TTL_S
    return {
        "challenge_id": cid,
        "prompt": "Confirm you are human by checking the CAPTCHA box.",
        "type": "checkbox",
    }


def verify_challenge(challenge_id: str, answer_str: str | bool | None) -> bool:
    """Validate checkbox completion; consumes the challenge (single use)."""
    _cleanup()
    if not challenge_id or answer_str is None:
        return False
    exp = _CHALLENGES.pop(challenge_id, None)
    if exp is None:
        return False
    if time.time() > exp:
        return False
    if isinstance(answer_str, bool):
        return answer_str
    ans = str(answer_str).strip().lower()
    return ans in {"1", "true", "yes", "on", "checked"}


def check_rate_limit(client_id: str) -> bool:
    """Return True when request is allowed by defence-only rate limiting."""
    _cleanup()
    now = time.time()
    window_start, count = _RATE_BUCKETS.get(client_id, (now, 0))
    if now - window_start > _RATE_WINDOW_S:
        window_start, count = now, 0

    count += 1
    _RATE_BUCKETS[client_id] = (window_start, count)
    return count <= _RATE_LIMIT_MAX_REQUESTS


def _read_state() -> dict[str, object]:
    if not _STATE_FILE.exists():
        return {"enabled": False, "updated_at": int(time.time())}
    try:
        data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"enabled": False, "updated_at": int(time.time())}
    enabled = bool(data.get("enabled", False))
    updated_at = int(data.get("updated_at", int(time.time())))
    return {"enabled": enabled, "updated_at": updated_at}


def _write_state(enabled: bool) -> dict[str, object]:
    state = {"enabled": bool(enabled), "updated_at": int(time.time())}
    _STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return state


def captcha_enabled() -> bool:
    """Return persisted CAPTCHA on/off state from defence/.captcha_state.json."""
    return bool(_read_state()["enabled"])


def set_captcha_enabled(enabled: bool) -> bool:
    """Persist CAPTCHA on/off state and return the resulting value."""
    state = _write_state(enabled)
    return bool(state["enabled"])


def _main() -> None:
    p = argparse.ArgumentParser(description="Toggle persisted CAPTCHA defence state.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--on", action="store_true", help="Enable CAPTCHA defence.")
    g.add_argument("--off", action="store_true", help="Disable CAPTCHA defence.")
    g.add_argument("--status", action="store_true", help="Show current CAPTCHA defence state.")
    args = p.parse_args()

    if args.on:
        state = _write_state(True)
        print(f"CAPTCHA defence enabled: {state['enabled']}")
        return
    if args.off:
        state = _write_state(False)
        print(f"CAPTCHA defence enabled: {state['enabled']}")
        return

    state = _read_state()
    print(
        f"CAPTCHA defence enabled: {state['enabled']} "
        f"(updated_at={state['updated_at']})"
    )


if __name__ == "__main__":
    _main()
