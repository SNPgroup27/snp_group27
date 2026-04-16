"""Simulated hospital datacenter API with IoMT-style endpoints.

Currently exposes:
- /api/cgm/readings      – legacy CGM-style ingest (random data)
- /api/appointments      – new appointment booking API backed by Kaggle CSV schema
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, List

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from app.metrics import METRICS

app = FastAPI(
    title="Simulated Hospital Datacenter",
    description="Prototype REST API ingesting CGM-style IoMT readings (coursework).",
    version="0.1.0",
)

_readings: list[dict[str, Any]] = []
_MAX_READINGS = 10_000


class CGMReading(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=128)
    glucose_mg_dl: float = Field(..., ge=0, le=1000)
    timestamp: datetime | None = None


class Appointment(BaseModel):
    appointment_id: str
    patient_id: str
    doctor_id: str
    appointment_date: str  # keep as strings matching CSV; parsing is optional for this coursework
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


@app.post("/api/cgm/readings")
async def post_cgm_reading(reading: CGMReading):
    ts = reading.timestamp or datetime.now(timezone.utc)
    row = {
        "device_id": reading.device_id,
        "glucose_mg_dl": reading.glucose_mg_dl,
        "timestamp": ts.isoformat(),
    }
    _readings.append(row)
    if len(_readings) > _MAX_READINGS:
        del _readings[: len(_readings) - _MAX_READINGS]
    METRICS.record_cgm_post()
    print(
        "[datacenter] accepted CGM reading "
        f"device={reading.device_id} glucose_mg_dl={reading.glucose_mg_dl}",
        flush=True,
    )
    return {"accepted": True, "id": len(_readings)}


@app.get("/api/cgm/readings")
async def list_cgm_readings(limit: int = 50):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be 1..500")
    return {"readings": _readings[-limit:]}


@app.get("/api/cgm/readings/latest/{device_id}")
async def latest_for_device(device_id: str):
    for r in reversed(_readings):
        if r["device_id"] == device_id:
            return r
    raise HTTPException(status_code=404, detail="no readings for device")


@app.post("/api/appointments")
async def post_appointment(appt: Appointment):
    """Accept one appointment booking request."""
    row = appt.model_dump()
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
    return {"accepted": True, "id": appt.appointment_id}


@app.get("/api/appointments")
async def list_appointments(limit: int = 50):
    """Return the most recent appointments (for spot-checking in the terminal)."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be 1..500")
    return {"appointments": _appointments[-limit:]}
