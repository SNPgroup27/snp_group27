"""Simulated hospital datacenter API for appointment bookings."""

from __future__ import annotations

import time
from typing import Any, List

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from starlette.responses import JSONResponse

from app.metrics import METRICS
from defence.captcha import (
    captcha_debug_snapshot,
    captcha_effective_enabled,
    check_rate_limit,
    create_challenge,
    verify_challenge,
)
from defence.http_firewall import http_firewall_status
from defence.syn_defence import syn_cookies_kernel_status

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


@app.middleware("http")
async def captcha_appointment_rate_gate(request: Request, call_next):
    """Reject excess POSTs before the route (and body parsing) when CAPTCHA defence is on.

    Registered after timing so this layer runs *first* on incoming requests (outer middleware).
    """
    if not captcha_effective_enabled() or request.method != "POST":
        return await call_next(request)
    if request.url.path != "/api/appointments":
        return await call_next(request)
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "rate limit exceeded (CAPTCHA defence active)"},
            headers={"Connection": "close"},
        )
    return await call_next(request)


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


@app.get("/api/defence/http-firewall")
async def http_fw_status():
    """Network-level ``SNP_HTTP`` iptables chain for the API port (see ``defence.http_firewall``)."""
    return http_firewall_status(8000)


@app.get("/api/defence/captcha-status")
async def captcha_status():
    """Show CAPTCHA on/off as this server process sees it (env + persisted file path)."""
    return captcha_debug_snapshot()


@app.get("/api/captcha/challenge")
async def captcha_challenge():
    """Return a one-time checkbox CAPTCHA token."""
    return create_challenge()


@app.post("/api/appointments")
async def post_appointment(appt: Appointment, request: Request):
    """Accept one appointment booking request."""
    if captcha_effective_enabled():
        # Per-IP rate limit is enforced in `captcha_appointment_rate_gate` (before this handler).
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
