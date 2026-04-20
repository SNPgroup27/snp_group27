"""Simulated hospital datacenter API for appointment bookings."""

from __future__ import annotations

import os
import time
from typing import Any, List

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.metrics import METRICS
from defence.captcha import (
    captcha_enabled,
    check_rate_limit,
    create_challenge,
    verify_challenge,
)
from defence.syn_cookies import syn_cookies_kernel_status

_CAPTCHA_ENV = "ENABLE_APPOINTMENT_CAPTCHA"


def _captcha_enabled() -> bool:
    env_val = os.environ.get(_CAPTCHA_ENV, "").strip().lower()
    if env_val in ("1", "true", "yes", "on"):
        return True
    if env_val in ("0", "false", "no", "off"):
        return False
    return captcha_enabled()

app = FastAPI(
    title="Simulated Hospital Datacenter",
    description="Prototype REST API ingesting appointment bookings (coursework).",
    version="0.1.0",
)


class Appointment(BaseModel):
    appointment_id: str
    patient_id: str
    doctor_id: str
    appointment_date: str  
    appointment_time: str
    reason_for_visit: str
    status: str
    captcha_challenge_id: str | None = None
    captcha_answer: str | None = None


_appointments: List[dict[str, Any]] = []
_MAX_APPOINTMENTS = 10_000


@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    start = time.perf_counter()
    try:
        response = await call_next(request)
        err = response.status_code >= 400
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        METRICS.record_request(elapsed_ms, err)
        return response
    except Exception:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        METRICS.record_request(elapsed_ms, True)
        raise


@app.get("/health")
async def health():
    return {"status": "ok", "service": "simulated-datacenter"}


@app.get("/api/metrics")
async def metrics():
    return METRICS.snapshot()


@app.get("/api/defence/syn-cookies")
async def syn_cookies_status():
    """Linux kernel SYN-cookie state (not configurable from Python — see defence/SYN_COOKIES.md)."""
    return syn_cookies_kernel_status()


@app.get("/api/captcha/challenge")
async def captcha_challenge():
    """Return a one-time checkbox CAPTCHA token."""
    return create_challenge()


@app.post("/api/appointments")
async def post_appointment(appt: Appointment, request: Request):
    """Accept one appointment booking request."""
    if _captcha_enabled():
        client_ip = request.client.host if request.client else "unknown"
        if not check_rate_limit(client_ip):
            raise HTTPException(status_code=429, detail="rate limit exceeded")

        cid = appt.captcha_challenge_id
        ans = appt.captcha_answer
        if not cid or ans is None or str(ans).strip() == "":
            raise HTTPException(
                status_code=400,
                detail="captcha_challenge_id and captcha_answer required when CAPTCHA is enabled",
            )
        if not verify_challenge(cid, ans):
            raise HTTPException(status_code=403, detail="invalid or expired CAPTCHA")

    row = appt.model_dump()
    row.pop("captcha_challenge_id", None)
    row.pop("captcha_answer", None)
    _appointments.append(row)
    if len(_appointments) > _MAX_APPOINTMENTS:
        del _appointments[: len(_appointments) - _MAX_APPOINTMENTS]
    print(
        "[datacenter] accepted appointment "
        f"id={appt.appointment_id} patient={appt.patient_id} "
        f"doctor={appt.doctor_id} date={appt.appointment_date} "
        f"time={appt.appointment_time}",
        flush=True,
    )
    METRICS.record_appointment_post()
    return {"accepted": True, "id": appt.appointment_id}


@app.get("/api/appointments")
async def list_appointments(limit: int = 50):
    """Return the most recent appointments (for spot-checking in the terminal)."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be 1..500")
    return {"appointments": _appointments[-limit:]}
