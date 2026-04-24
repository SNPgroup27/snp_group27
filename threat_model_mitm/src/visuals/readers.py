"""Data readers for the CGM MITM visual monitoring app.

Reads from existing log files, SQLite DB, and JSONL files produced by
the CGM simulator, API gateway, and attacker node. All functions return
empty results if the source file is absent or unreadable.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

# CGM log line patterns
_SEND_RE = re.compile(
    r"cgm send id=(\d+) ts=(\S+) glucose=([\d.]+) alert=(\w+)"
)
_STATUS_RE = re.compile(r"cgm (accepted|rejected) status=(\d+)")
_READY_RE = re.compile(r"cgm ready\b.+\bpatient=(\w+)")
_ALERT_RE = re.compile(
    r"alert row_id=(\d+) patient=(\S+) glucose=([\d.]+) "
    r"device_alert=(\w+) gateway_alert=(\w+) mismatch=(\d+) "
    r"ts=(\S+) received_at=(\S+) latency_ms=([\d.]+)"
)


def parse_cgm_log(log_path: Path) -> list[dict[str, Any]]:
    """Parse cgm_sent_readings.log into a list of reading dicts.

    Each reading contains: id, timestamp, glucose_mmol, alert_level,
    accepted (bool or None), status_code (int or None).

    Returns an empty list if the file is absent or cannot be read.
    """
    if not log_path.exists():
        return []

    readings: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None

    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                m = _SEND_RE.search(line)
                if m:
                    # Flush any unresolved pending send (e.g. log truncated mid-flight)
                    if pending is not None:
                        readings.append(pending)
                    pending = {
                        "id": int(m.group(1)),
                        "timestamp": m.group(2),
                        "glucose_mmol": float(m.group(3)),
                        "alert_level": m.group(4),
                        "accepted": None,
                        "status_code": None,
                    }
                    continue

                if pending is not None:
                    sm = _STATUS_RE.search(line)
                    if sm:
                        pending["accepted"] = sm.group(1) == "accepted"
                        pending["status_code"] = int(sm.group(2))
                        readings.append(pending)
                        pending = None
                    elif (
                        "cgm timeout" in line
                        or "cgm connection_error" in line
                        or "cgm error=" in line
                    ):
                        pending["accepted"] = False
                        readings.append(pending)
                        pending = None

        # Include a send that arrived with no status yet (packet in flight)
        if pending is not None:
            readings.append(pending)

    except OSError:
        return []

    return readings


def get_cgm_patient_id(log_path: Path) -> str | None:
    """Extract the patient ID from the CGM log ready line."""
    if not log_path.exists():
        return None
    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                m = _READY_RE.search(line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def query_gateway_db(
    db_path: Path,
    patient_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return glucose readings from the gateway SQLite DB, newest first.

    Opened read-only via URI to avoid interfering with the gateway write path.
    Returns an empty list if the DB is absent or cannot be opened.
    """
    if not db_path.exists():
        return []

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        if patient_id:
            rows = conn.execute(
                "SELECT * FROM glucose_readings "
                "WHERE patient_id = ? ORDER BY id DESC LIMIT ?",
                (patient_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM glucose_readings ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except (sqlite3.Error, OSError):
        return []


def get_gateway_patient_ids(db_path: Path) -> list[str]:
    """Return all distinct patient IDs present in the gateway DB."""
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        rows = conn.execute(
            "SELECT DISTINCT patient_id FROM glucose_readings ORDER BY patient_id"
        ).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except (sqlite3.Error, OSError):
        return []


def parse_gateway_alert_log(
    log_path: Path,
    patient_id: str | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Parse recent LOW/HIGH gateway alerts from critical_alerts.log."""
    if not log_path.exists():
        return []

    alerts: list[dict[str, Any]] = []
    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                match = _ALERT_RE.search(line)
                if not match:
                    continue
                alert = {
                    "row_id": int(match.group(1)),
                    "patient_id": match.group(2),
                    "glucose_mmol": float(match.group(3)),
                    "device_alert_level": match.group(4),
                    "gateway_alert_level": match.group(5),
                    "alert_mismatch": int(match.group(6)),
                    "timestamp": match.group(7),
                    "received_at": match.group(8),
                    "latency_ms": float(match.group(9)),
                }
                if patient_id and alert["patient_id"] != patient_id:
                    continue
                alerts.append(alert)
    except OSError:
        return []

    return list(reversed(alerts[-limit:]))


def parse_attack_jsonl(jsonl_path: Path) -> list[dict[str, Any]]:
    """Parse attack_packet_map.jsonl into a list of event dicts (oldest first).

    Returns an empty list if the file is absent or cannot be read.
    Skips malformed lines silently.
    """
    if not jsonl_path.exists():
        return []

    events: list[dict[str, Any]] = []
    try:
        with open(jsonl_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []

    return events


def read_attack_summary(summary_path: Path) -> dict[str, Any]:
    """Read attack_summary.json. Returns an empty dict if absent or invalid."""
    if not summary_path.exists():
        return {}
    try:
        with open(summary_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
