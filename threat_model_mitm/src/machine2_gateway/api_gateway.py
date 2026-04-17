"""API Gateway: receives CGM readings, stores them in SQLite, logs abnormal alerts.

Run directly from this folder with ``python3 api_gateway.py`` or launch the
combined workflow from ``python3 ../main_cgm_api.py --mode``.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request

_BASE = Path(__file__).parent
CONFIG_FILE = _BASE / "config.json"
LOG_DIR = _BASE / "logs"

_REQUIRED_FIELDS = ("patient_id", "timestamp", "glucose_mmol", "alert_level")
_ABNORMAL_LEVELS = frozenset(("LOW", "HIGH"))

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
CREATE INDEX IF NOT EXISTS idx_patient ON glucose_readings(patient_id);
CREATE INDEX IF NOT EXISTS idx_alert   ON glucose_readings(gateway_alert_level);
"""


def _reset_file(filepath: Path) -> bool:
    """Delete an existing runtime file and report whether it existed."""
    if filepath.exists():
        filepath.unlink()
        return True
    return False


def _get_loggers() -> tuple[logging.Logger, logging.Logger]:
    """Return fresh request and alert loggers for this run."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    request_fmt = logging.Formatter("%(levelname)s %(message)s")
    alert_fmt = logging.Formatter("%(levelname)s %(message)s")
    request_log_path = LOG_DIR / "api_requests.log"
    alert_log_path = LOG_DIR / "critical_alerts.log"
    request_log_reset = _reset_file(request_log_path)
    alert_log_reset = _reset_file(alert_log_path)

    req_log = logging.getLogger("gateway.requests")
    for handler in list(req_log.handlers):
        handler.close()
        req_log.removeHandler(handler)
    req_log.setLevel(logging.INFO)
    req_handler = logging.FileHandler(request_log_path)
    req_handler.setFormatter(request_fmt)
    req_log.addHandler(req_handler)
    if request_log_reset:
        req_log.warning("gateway reset existing api_requests.log")

    alert_log = logging.getLogger("gateway.alerts")
    for handler in list(alert_log.handlers):
        handler.close()
        alert_log.removeHandler(handler)
    alert_log.propagate = False
    alert_log.setLevel(logging.WARNING)
    alert_handler = logging.FileHandler(alert_log_path)
    alert_handler.setFormatter(alert_fmt)
    alert_log.addHandler(alert_handler)
    if alert_log_reset:
        alert_log.warning("gateway reset existing critical_alerts.log")

    return req_log, alert_log


def load_config(config_path: Path = CONFIG_FILE) -> dict[str, Any]:
    """Load gateway configuration from JSON."""
    with open(config_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _utc_now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO 8601 timestamp, defaulting naive values to UTC."""
    normalised = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalised)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _latency_ms(packet_timestamp: str, received_at: str) -> float:
    """Calculate end-to-end latency in milliseconds."""
    sent_at = _parse_iso_datetime(packet_timestamp)
    received = _parse_iso_datetime(received_at)
    latency = round((received - sent_at).total_seconds() * 1000, 3)
    return max(latency, 0.0)


def _derive_alert_level(glucose_mmol: float) -> str:
    """Derive the gateway alert level from glucose mmol/L."""
    if glucose_mmol < 3.9:
        return "LOW"
    if glucose_mmol <= 10.0:
        return "NORMAL"
    return "HIGH"


class APIGateway:
    """Flask API gateway for the CGM MITM lab demo.

    Routes:
        POST /api/glucose   Accept and persist a reading.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5050,
        db_path: Path = _BASE / "hospital.db",
        reset_database_on_start: bool = True,
        debug: bool = False,
        mode: str = "gateway",
    ) -> None:
        """
        Args:
            host:    Flask bind address.
            port:    Flask bind port.
            db_path: Path to the SQLite database file (created if absent).
            reset_database_on_start: Whether to delete the runtime DB on startup.
            debug:   Enable Flask debug mode.
            mode:    Workflow mode label for logging context.
        """
        self._host = host
        self._port = port
        self._db_path = Path(db_path).resolve()
        self._reset_database_on_start = reset_database_on_start
        self._debug = debug
        self._mode = mode

        self._req_log, self._alert_log = _get_loggers()
        self._reset_database()
        self._app = Flask(__name__)
        self._init_db()
        self._register_routes()

        self._req_log.info(
            "gateway ready mode=%s host=%s port=%d db=%s",
            mode,
            host,
            port,
            self._db_path,
        )

    @classmethod
    def from_config(cls, config_path: Path = CONFIG_FILE) -> "APIGateway":
        """Build a gateway instance from a config file."""
        config = load_config(config_path)
        db_path = Path(config.get("database_path", "hospital.db"))
        if not db_path.is_absolute():
            db_path = (config_path.parent / db_path).resolve()

        return cls(
            host=config.get("host", "0.0.0.0"),
            port=int(config.get("port", 5050)),
            db_path=db_path,
            reset_database_on_start=bool(config.get("reset_database_on_start", True)),
            debug=bool(config.get("debug", False)),
            mode="gateway",
        )

    # Database

    def _reset_database(self) -> None:
        """Reset the runtime database file on startup."""
        if not self._reset_database_on_start:
            self._req_log.info("gateway preserve existing database path=%s", self._db_path)
            return
        if self._db_path.exists():
            self._db_path.unlink()
            self._req_log.warning("gateway reset existing database path=%s", self._db_path)
            self._alert_log.warning("gateway reset existing database path=%s", self._db_path)

    def _db(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.executescript(_SCHEMA)

    # Alert logging

    def _log_alert(
        self,
        row_id: int,
        patient_id: str,
        glucose: float,
        device_alert: str,
        gateway_alert: str,
        mismatch: int,
        ts: str,
        received_at: str,
        latency_ms: float,
    ) -> None:
        self._alert_log.warning(
            "alert row_id=%d patient=%s glucose=%.1f device_alert=%s gateway_alert=%s mismatch=%d "
            "ts=%s received_at=%s latency_ms=%.3f",
            row_id,
            patient_id,
            glucose,
            device_alert,
            gateway_alert,
            mismatch,
            ts,
            received_at,
            latency_ms,
        )

    # Routes

    def _register_routes(self) -> None:
        app = self._app

        @app.route("/api/glucose", methods=["POST"])
        def receive_glucose() -> tuple[Response, int]:
            """Accept a CGM packet and store it.

            Body: {"patient_id", "device_id"(opt), "timestamp",
                   "glucose_mmol", "alert_level"}
            """
            data: Any = request.get_json(silent=True)
            if not data:
                return jsonify({"status": "error", "message": "No JSON body"}), 400

            missing = [f for f in _REQUIRED_FIELDS if f not in data]
            if missing:
                return jsonify({"status": "error", "message": f"Missing: {missing}"}), 400

            received_at = _utc_now_iso()
            try:
                glucose_mmol = float(data["glucose_mmol"])
                device_alert = str(data["alert_level"])
                gateway_alert = _derive_alert_level(glucose_mmol)
                alert_mismatch = int(device_alert != gateway_alert)
                latency_ms = _latency_ms(data["timestamp"], received_at)
                with self._db() as conn:
                    cursor = conn.execute(
                        """INSERT INTO glucose_readings
                               (patient_id, device_id, timestamp,
                                glucose_mmol, device_alert_level, gateway_alert_level,
                                alert_mismatch, received_at, latency_ms)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            data["patient_id"],
                            data.get("device_id"),
                            data["timestamp"],
                            glucose_mmol,
                            device_alert,
                            gateway_alert,
                            alert_mismatch,
                            received_at,
                            latency_ms,
                        ),
                    )
                    row_id = cursor.lastrowid

                self._req_log.info(
                    "gateway stored id=%d patient=%s glucose=%.1f device_alert=%s gateway_alert=%s "
                    "mismatch=%d received_at=%s latency_ms=%.3f",
                    row_id,
                    data["patient_id"],
                    glucose_mmol,
                    device_alert,
                    gateway_alert,
                    alert_mismatch,
                    received_at,
                    latency_ms,
                )
                if alert_mismatch:
                    self._req_log.warning(
                        "gateway alert_mismatch id=%d patient=%s glucose=%.1f device_alert=%s gateway_alert=%s",
                        row_id,
                        data["patient_id"],
                        glucose_mmol,
                        device_alert,
                        gateway_alert,
                    )

                if gateway_alert in _ABNORMAL_LEVELS:
                    self._req_log.warning(
                        "gateway abnormal level=%s patient=%s glucose=%.1f",
                        gateway_alert,
                        data["patient_id"],
                        glucose_mmol,
                    )
                    self._log_alert(
                        row_id,
                        data["patient_id"],
                        glucose_mmol,
                        device_alert,
                        gateway_alert,
                        alert_mismatch,
                        data["timestamp"],
                        received_at,
                        latency_ms,
                    )

                return jsonify(
                    {
                        "status": "success",
                        "id": row_id,
                        "received_at": received_at,
                        "latency_ms": latency_ms,
                    }
                ), 200

            except sqlite3.Error as exc:
                self._req_log.error("gateway db_error=%s", exc)
                return jsonify({"status": "error", "message": "Database error"}), 500
            except ValueError as exc:
                self._req_log.error("gateway timestamp_error=%s", exc)
                return jsonify({"status": "error", "message": "Invalid timestamp"}), 400

        @app.route("/health", methods=["GET"])
        def health() -> tuple[Response, int]:
            """Simple readiness probe for launcher/startup checks."""
            return jsonify({"status": "ok", "service": "api_gateway"}), 200

    # Entry point

    def run(self) -> None:
        """Start the Flask development server (blocking)."""
        self._app.run(host=self._host, port=self._port, debug=self._debug)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )
    APIGateway.from_config(CONFIG_FILE).run()
