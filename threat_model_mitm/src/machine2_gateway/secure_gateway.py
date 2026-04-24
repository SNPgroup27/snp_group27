from __future__ import annotations

import json
import logging
import sqlite3
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request

_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from security_core.ai_ids import AnomalyDetector
from security_core.e2e_crypto import decrypt_payload

_BASE = Path(__file__).parent
_THREAT_MODEL_ROOT = _BASE.parents[1]
_CERTS_DIR = _THREAT_MODEL_ROOT / "certs"
_REQUIRED_FIELDS = ("patient_id", "timestamp", "glucose_mmol", "alert_level")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS glucose_readings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id           TEXT  NOT NULL,
    device_id            TEXT,
    timestamp            TEXT  NOT NULL,
    glucose_mmol         REAL  NOT NULL,
    device_alert_level   TEXT  NOT NULL,
    gateway_alert_level  TEXT  NOT NULL,
    alert_mismatch       INTEGER NOT NULL,
    received_at          TEXT  NOT NULL,
    latency_ms           REAL  NOT NULL
);
"""

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("secure_gateway")


def _parse_iso_datetime(value: str) -> datetime:
    normalised = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalised)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _derive_alert_level(glucose_mmol: float) -> str:
    if glucose_mmol < 3.9:
        return "LOW"
    if glucose_mmol <= 10.0:
        return "NORMAL"
    return "HIGH"


def _latency_ms(packet_timestamp: str, received_at: str) -> float:
    sent_at = _parse_iso_datetime(packet_timestamp)
    recv_at = _parse_iso_datetime(received_at)
    return max(round((recv_at - sent_at).total_seconds() * 1000, 3), 0.0)


def _build_server_ssl_context(certs_dir: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(certs_dir / "server.crt"), str(certs_dir / "server.key"))
    ctx.load_verify_locations(cafile=str(certs_dir / "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


DB_PATH = _THREAT_MODEL_ROOT / "data" / "gateway" / "hospital.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _db() as conn:
        conn.executescript(_SCHEMA)


_init_db()
detector = AnomalyDetector(DB_PATH)
app = Flask(__name__)


@app.route("/api/glucose", methods=["POST"])
def receive_glucose() -> tuple[Response, int]:
    encrypted = request.get_json(silent=True)
    if not encrypted or not isinstance(encrypted, dict):
        return jsonify({"status": "error", "message": "No JSON body"}), 400

    try:
        data = decrypt_payload(encrypted)
        log.info("[CRYPTO] Decryption OK")
    except ValueError:
        log.warning("[CRYPTO] Decryption FAILED - possible tamper or wrong key")
        return jsonify({"status": "error", "message": "Decryption failed"}), 400

    packet_timestamp_raw = data.get("timestamp")
    if packet_timestamp_raw is None:
        return jsonify({"status": "error", "message": "Missing timestamp"}), 400
    try:
        packet_epoch = _parse_iso_datetime(str(packet_timestamp_raw)).timestamp()
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid timestamp"}), 400

    age = abs(time.time() - packet_epoch)
    if age > 10.0:
        log.warning("[REPLAY] REPLAY ATTACK DETECTED age=%.1fs", age)
        return jsonify(
            {"error": "replay_protection_triggered", "age_seconds": age}
        ), 403
    log.info("[REPLAY] Timestamp OK age=%.2fs", age)

    missing = [f for f in _REQUIRED_FIELDS if f not in data]
    if missing:
        return jsonify({"status": "error", "message": f"Missing: {missing}"}), 400

    received_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    try:
        glucose_mmol = float(data["glucose_mmol"])
        device_alert = str(data["alert_level"])
        gateway_alert = _derive_alert_level(glucose_mmol)
        alert_mismatch = int(device_alert != gateway_alert)
        latency = _latency_ms(str(data["timestamp"]), received_at)
        with _db() as conn:
            cursor = conn.execute(
                """INSERT INTO glucose_readings
                   (patient_id, device_id, timestamp, glucose_mmol, device_alert_level,
                    gateway_alert_level, alert_mismatch, received_at, latency_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(data["patient_id"]),
                    data.get("device_id"),
                    str(data["timestamp"]),
                    glucose_mmol,
                    device_alert,
                    gateway_alert,
                    alert_mismatch,
                    received_at,
                    latency,
                ),
            )
            row_id = int(cursor.lastrowid)
    except (sqlite3.Error, ValueError) as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500

    ids_state = detector.evaluate_current_state()
    if ids_state.get("mitm_anomaly"):
        log.warning("[IDS] ANOMALY DETECTED: %s", ids_state.get("anomaly_reason"))
    else:
        log.info(
            "[IDS] Traffic profile NORMAL score=%.4f",
            ids_state.get("decision_function", 0),
        )

    log.info(
        "[GW] stored id=%d patient=%s glucose=%.1f alert=%s mismatch=%d latency=%.1fms",
        row_id,
        data["patient_id"],
        glucose_mmol,
        gateway_alert,
        alert_mismatch,
        latency,
    )

    return jsonify(
        {
            "status": "success",
            "id": row_id,
            "received_at": received_at,
            "latency_ms": latency,
            "ids": ids_state,
        }
    ), 200


@app.route("/health", methods=["GET"])
def health() -> tuple[Response, int]:
    return jsonify({"status": "ok", "service": "secure_gateway"}), 200


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5051
    use_tls = "--no-tls" not in sys.argv
    if use_tls:
        log.info("Starting SECURE gateway on port %d (mTLS)", port)
        ssl_ctx = _build_server_ssl_context(_CERTS_DIR)
        app.run(host="127.0.0.1", port=port, debug=False, ssl_context=ssl_ctx)
    else:
        log.info("Starting gateway on port %d (no TLS - test mode)", port)
        app.run(host="127.0.0.1", port=port, debug=False)
