"""Lightweight checkbox-style CAPTCHA for POST /api/appointments.

Also provides a tiny CLI to toggle CAPTCHA state:

    python defence/captcha.py --on
    python defence/captcha.py --off
    python defence/captcha.py --status
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from pathlib import Path

# ENABLE_*: when set to 1/true/on or 0/false/off, overrides persisted file (empty = no override).
CAPTCHA_ENV_VAR = "ENABLE_APPOINTMENT_CAPTCHA"
# Kill-switch: when truthy, CAPTCHA is always off (overrides ENABLE_* and the JSON file).
CAPTCHA_DISABLE_ENV_VAR = "DISABLE_APPOINTMENT_CAPTCHA"

_CHALLENGES: dict[str, float] = {}
_TTL_S = 300.0
_MAX_CHALLENGES = 5000
_STATE_FILE = Path(__file__).with_name(".captcha_state.json")
_RATE_WINDOW_S = 10.0
# Softer cap if something calls check_rate_limit while CAPTCHA is off (not used for /api/appointments then).
_RATE_LIMIT_MAX_REQUESTS = 30
# Tighter per-IP cap while CAPTCHA defence is on so the app rejects floods before full POST handling.
_RATE_CAPTCHA_DEFENCE_MAX = 12
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


def _effective_rate_max() -> int:
    return _RATE_CAPTCHA_DEFENCE_MAX if captcha_effective_enabled() else _RATE_LIMIT_MAX_REQUESTS


def check_rate_limit(client_id: str) -> bool:
    """Return True when request is allowed by defence-only rate limiting (stricter when CAPTCHA is on)."""
    _cleanup()
    now = time.time()
    window_start, count = _RATE_BUCKETS.get(client_id, (now, 0))
    if now - window_start > _RATE_WINDOW_S:
        window_start, count = now, 0

    count += 1
    _RATE_BUCKETS[client_id] = (window_start, count)
    return count <= _effective_rate_max()


def _coerce_enabled_value(raw: object) -> bool:
    """Avoid bool('false') == True if JSON stores the string 'false'."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return raw != 0
    if isinstance(raw, str):
        s = raw.strip().lower()
        if s in ("0", "false", "no", "off", ""):
            return False
        if s in ("1", "true", "yes", "on"):
            return True
        return False
    return False


def _read_state() -> dict[str, object]:
    if not _STATE_FILE.exists():
        return {"enabled": False, "updated_at": int(time.time())}
    try:
        data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"enabled": False, "updated_at": int(time.time())}
    enabled = _coerce_enabled_value(data.get("enabled", False))
    updated_at = int(data.get("updated_at", int(time.time())))
    return {"enabled": enabled, "updated_at": updated_at}


def _write_state(enabled: bool) -> dict[str, object]:
    state = {"enabled": bool(enabled), "updated_at": int(time.time())}
    _STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return state


def captcha_enabled() -> bool:
    """Return persisted CAPTCHA on/off state from defence/.captcha_state.json."""
    return bool(_read_state()["enabled"])


def _env_truthy(name: str) -> bool:
    v = os.environ.get(name, "").strip().lower()
    return v in ("1", "true", "yes", "on")


def captcha_env_override() -> bool | None:
    """
    If ENABLE_APPOINTMENT_CAPTCHA is set to a non-empty value, return True/False and ignore the file.
    If unset or empty string, return None (use persisted file via captcha_enabled()).
    """
    raw = os.environ.get(CAPTCHA_ENV_VAR)
    if raw is None or str(raw).strip() == "":
        return None
    env_val = str(raw).strip().lower()
    if env_val in ("1", "true", "yes", "on"):
        return True
    if env_val in ("0", "false", "no", "off", "disabled"):
        return False
    # Unknown non-empty value: do not override (use persisted file)
    return None


def captcha_effective_enabled() -> bool:
    """What the API should use: DISABLE_* killswitch, then ENABLE_* override, else persisted JSON."""
    if _env_truthy(CAPTCHA_DISABLE_ENV_VAR):
        return False
    o = captcha_env_override()
    if o is not None:
        return o
    return captcha_enabled()


def captcha_debug_snapshot() -> dict[str, object]:
    """What the running server process sees (paths, env, effective flag). Lab / debugging only."""
    return {
        "captcha_required": captcha_effective_enabled(),
        "persisted_enabled": captcha_enabled(),
        "persisted_state": dict(_read_state()),
        "persisted_state_file": str(_STATE_FILE.resolve()),
        "captcha_module_file": str(Path(__file__).resolve()),
        "env_enable_raw": os.environ.get(CAPTCHA_ENV_VAR, ""),
        "env_disable_raw": os.environ.get(CAPTCHA_DISABLE_ENV_VAR, ""),
        "env_enable_interpretation": captcha_env_override(),
        "disable_kill_switch_active": _env_truthy(CAPTCHA_DISABLE_ENV_VAR),
    }


def set_captcha_enabled(enabled: bool) -> bool:
    """Persist CAPTCHA on/off state and return the resulting value."""
    state = _write_state(enabled)
    return bool(state["enabled"])


def _print_env_override_hint() -> None:
    if _env_truthy(CAPTCHA_DISABLE_ENV_VAR):
        print(
            f"NOTE: {CAPTCHA_DISABLE_ENV_VAR} is set — CAPTCHA is forced OFF in this shell "
            f"(overrides {CAPTCHA_ENV_VAR} and the JSON file)."
        )
    ov = captcha_env_override()
    raw = os.environ.get(CAPTCHA_ENV_VAR, "")
    if ov is True:
        print(
            f"NOTE: {CAPTCHA_ENV_VAR}={raw!r} in this shell forces CAPTCHA ON for any process "
            f"started with that env (overrides defence/.captcha_state.json). "
            f"Restart uvicorn with the variable unset or set to 0, or set {CAPTCHA_DISABLE_ENV_VAR}=1."
        )
    elif ov is False:
        print(f"NOTE: {CAPTCHA_ENV_VAR}={raw!r} forces CAPTCHA OFF regardless of the file.")
    else:
        print(f"No {CAPTCHA_ENV_VAR} override in this shell (uvicorn uses file unless its own env differs).")


def _main() -> None:
    p = argparse.ArgumentParser(description="Toggle persisted CAPTCHA defence state.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--on", action="store_true", help="Enable CAPTCHA defence.")
    g.add_argument("--off", action="store_true", help="Disable CAPTCHA defence.")
    g.add_argument("--status", action="store_true", help="Show current CAPTCHA defence state.")
    args = p.parse_args()

    if args.on:
        state = _write_state(True)
        print(f"Persisted CAPTCHA (file): enabled={state['enabled']}")
        _print_env_override_hint()
        return
    if args.off:
        state = _write_state(False)
        print(f"Persisted CAPTCHA (file): enabled={state['enabled']}")
        _print_env_override_hint()
        return

    state = _read_state()
    print(
        f"Persisted CAPTCHA (file): enabled={state['enabled']} "
        f"(updated_at={state['updated_at']})"
    )
    _print_env_override_hint()
    print(f"Effective in this shell (env + file): {captcha_effective_enabled()}")


if __name__ == "__main__":
    _main()
