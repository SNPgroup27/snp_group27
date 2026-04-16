"""
Appointment datastream built from data/appointments.csv.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Dict


DATA_PATH = Path(__file__).resolve().parent / "data" / "appointments.csv"


@dataclass
class AppointmentRow:
    appointment_id: str
    patient_id: str
    doctor_id: str
    appointment_date: str
    appointment_time: str
    reason_for_visit: str
    status: str

    def to_payload(self) -> Dict[str, str]:
        return {
            "appointment_id": self.appointment_id,
            "patient_id": self.patient_id,
            "doctor_id": self.doctor_id,
            "appointment_date": self.appointment_date,
            "appointment_time": self.appointment_time,
            "reason_for_visit": self.reason_for_visit,
            "status": self.status,
        }


def _load_all() -> List[AppointmentRow]:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"{DATA_PATH} not found. "
        )
    rows: List[AppointmentRow] = []
    with DATA_PATH.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            rows.append(
                AppointmentRow(
                    appointment_id=raw["appointment_id"],
                    patient_id=raw["patient_id"],
                    doctor_id=raw["doctor_id"],
                    appointment_date=raw["appointment_date"],
                    appointment_time=raw["appointment_time"],
                    reason_for_visit=raw["reason_for_visit"],
                    status=raw["status"],
                )
            )
    if not rows:
        raise RuntimeError(f"No rows loaded from {DATA_PATH}")
    return rows


_APPOINTMENTS: List[AppointmentRow] | None = None
_INDEX: int = 0


def _ensure_loaded() -> List[AppointmentRow]:
    global _APPOINTMENTS
    if _APPOINTMENTS is None:
        _APPOINTMENTS = _load_all()
    return _APPOINTMENTS


def next_appointment() -> Dict[str, str]:
    """Return the next appointment row cycling when end is hit."""
    global _INDEX
    rows = _ensure_loaded()
    row = rows[_INDEX]
    _INDEX = (_INDEX + 1) % len(rows)
    return row.to_payload()


def iter_appointments() -> Iterator[Dict[str, str]]:
    while True:
        yield next_appointment()

