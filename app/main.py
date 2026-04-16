"""Simulated hospital datacenter API for appointment bookings."""

from __future__ import annotations

import time
from typing import Any, List

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from app.metrics import METRICS

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


@app.post("/api/appointments")
async def post_appointment(appt: Appointment):
    """Accept one appointment booking request."""
    _appointments.append(appt.model_dump())
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
