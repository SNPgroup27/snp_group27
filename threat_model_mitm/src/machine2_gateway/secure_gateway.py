from __future__ import annotations

import json
import logging
import sqlite3
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request

from security_core.ai_ids import AnomalyDetector
from security_core.e2e_crypto import decrypt_payload

_BASE = Path(__file__).parent
_CONFIG_FILE = _BASE / "config.json"
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


def load_config(config_path: Path = _CONFIG_FILE) -> dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


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


class SecureAPIGateway:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5050,
        db_path: Path = _BASE / "hospital.db",
        debug: bool = False,
        certs_dir: Path | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._db_path = Path(db_path).resolve()
        self._debug = debug
        self._certs_dir = Path(certs_dir) if certs_dir is not None else _CERTS_DIR
        self._app = Flask(__name__)
        self._detector = AnomalyDetector(self._db_path)
        self._init_db()
        self._register_routes()

    @classmethod
    def from_config(cls, config_path: Path = _CONFIG_FILE) -> "SecureAPIGateway":
        cfg = load_config(config_path)
        db_path = Path(cfg.get("database_path", "hospital.db"))
        if not db_path.is_absolute():
            db_path = (config_path.parent / db_path).resolve()
        return cls(
            host=str(cfg.get("host", "0.0.0.0")),
            port=int(cfg.get("port", 5050)),
            db_path=db_path,
            debug=bool(cfg.get("debug", False)),
        )

    def _db(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.executescript(_SCHEMA)

    def _invoke_ids_assume_breach(self) -> dict[str, Any]:
        return self._detector.evaluate_current_state()

    def _register_routes(self) -> None:
        app = self._app

        @app.route("/api/glucose", methods=["POST"])
        def receive_glucose() -> tuple[Response, int]:
            encrypted = request.get_json(silent=True)
            if not encrypted or not isinstance(encrypted, dict):
                return jsonify({"status": "error", "message": "No JSON body"}), 400

            try:
                data = decrypt_payload(encrypted)
            except ValueError:
                return jsonify({"status": "error", "message": "Decryption failed"}), 400

            packet_timestamp_raw = data.get("timestamp")
            if packet_timestamp_raw is None:
                return jsonify({"status": "error", "message": "Missing: ['timestamp']"}), 400
            try:
                packet_epoch = _parse_iso_datetime(str(packet_timestamp_raw)).timestamp()
            except ValueError:
                return jsonify({"status": "error", "message": "Invalid timestamp"}), 400
            if abs(time.time() - packet_epoch) > 10.0:
                print("[!] REPLAY ATTACK DETECTED")
                return jsonify({"error": "replay_protection_triggered"}), 403

            missing = [f for f in _REQUIRED_FIELDS if f not in data]
            if missing:
                ids_state = self._invoke_ids_assume_breach()
                return jsonify({"status": "error", "message": f"Missing: {missing}", "ids": ids_state}), 400

            received_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            try:
                glucose_mmol = float(data["glucose_mmol"])
                device_alert = str(data["alert_level"])
                gateway_alert = _derive_alert_level(glucose_mmol)
                alert_mismatch = int(device_alert != gateway_alert)
                latency_ms = _latency_ms(str(data["timestamp"]), received_at)
                with self._db() as conn:
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
                            latency_ms,
                        ),
                    )
                    row_id = int(cursor.lastrowid)
            except (sqlite3.Error, ValueError):
                return jsonify({"status": "error", "message": "Storage/validation error"}), 500

            # Assume breach: run IDS even when mTLS and decryption already succeeded.
            ids_state = self._invoke_ids_assume_breach()
            return jsonify(
                {
                    "status": "success",
                    "id": row_id,
                    "received_at": received_at,
                    "latency_ms": latency_ms,
                    "ids": ids_state,
                }
            ), 200

        @app.route("/health", methods=["GET"])
        def health() -> tuple[Response, int]:
            return jsonify({"status": "ok", "service": "secure_gateway"}), 200

    def run(self) -> None:
        self._app.run(
            host=self._host,
            port=self._port,
            debug=self._debug,
            ssl_context=_build_server_ssl_context(self._certs_dir),
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    SecureAPIGateway.from_config(_CONFIG_FILE).run()
