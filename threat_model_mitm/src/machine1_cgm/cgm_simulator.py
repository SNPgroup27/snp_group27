"""CGM simulator: replays preprocessed patient packet traces over HTTP.

Packet files are derived from the GlucoBench benchmark dataset:
  - Rows grouped by user_id and sorted chronologically before export.
  - Glucose values converted from mg/dL to mmol/L.
  - Alert levels: LOW (<3.9 mmol/L), NORMAL (3.9-10.0), HIGH (>10.0).
  - Runtime packet timestamps are injected at send time.

Launch the simulator via ``python3 ../main_cgm_api.py --mode cgm``.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

_BASE = Path(__file__).parent
CONFIG_FILE = _BASE / "config.json"
LOG_DIR = _BASE / "logs"
_LOG_NAME = "cgm.simulator"


def _reset_file(filepath: Path) -> bool:
    """Delete an existing runtime file and report whether it existed."""
    if filepath.exists():
        filepath.unlink()
        return True
    return False


def _get_logger() -> logging.Logger:
    """Return the CGM logger with a fresh file handler for this run."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / "cgm_sent_readings.log"
    log_reset = _reset_file(log_path)
    log = logging.getLogger(_LOG_NAME)
    for handler in list(log.handlers):
        handler.close()
        log.removeHandler(handler)

    log.setLevel(logging.INFO)
    fh = logging.FileHandler(log_path)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(fh)
    if log_reset:
        log.warning("cgm reset existing cgm_sent_readings.log")
    return log


def load_config(config_path: Path = CONFIG_FILE) -> dict[str, Any]:
    """Load simulator configuration from JSON."""
    with open(config_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


class CGMSimulator:
    """Replays a pre-processed CGM packet trace to a hospital API gateway."""

    def __init__(
        self,
        api_endpoint: str,
        packet_file: Path,
        interval_seconds: float = 300.0,
        loop: bool = True,
        mode: str = "cgm",
    ) -> None:
        """
        Args:
            api_endpoint:     Full URL of the gateway POST endpoint.
            packet_file:      Path to the pre-processed JSON packet trace.
            interval_seconds: Delay between packets (default 300 s).
            loop:             Whether to replay continuously after the final packet.
            mode:             Workflow mode label for logging context.
        """
        self._api_endpoint = api_endpoint
        self._interval_seconds = interval_seconds
        self._loop = loop
        self._mode = mode
        self._trace: list[dict[str, Any]] = self._load_trace(packet_file)
        self._patient_id = self._derive_patient_id(self._trace)
        self._index: int = 0
        self._log = _get_logger()

        self._log.info(
            "cgm ready mode=%s patient=%s interval=%ss loop=%s trace=%s packets=%d",
            mode,
            self._patient_id,
            interval_seconds,
            loop,
            packet_file.name,
            len(self._trace),
        )
        self._log.info("cgm endpoint=%s", api_endpoint)

    @staticmethod
    def _load_trace(filepath: Path) -> list[dict[str, Any]]:
        """Load and validate a patient packet JSON file."""
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError(f"Expected a JSON list in {filepath}")
        return data

    @staticmethod
    def _derive_patient_id(trace: list[dict[str, Any]]) -> str:
        """Read the patient identifier from the packet trace."""
        if not trace:
            raise ValueError("Packet trace is empty")
        patient_id = trace[0].get("patient_id")
        if not patient_id:
            raise ValueError("Packet trace is missing patient_id")
        return str(patient_id)

    def _next_packet(self) -> dict[str, Any] | None:
        """Return the next packet or stop at the end when looping is disabled."""
        if not self._trace:
            return None
        if not self._loop and self._index >= len(self._trace):
            return None

        packet = self._trace[self._index % len(self._trace)]
        self._index += 1
        return packet

    @staticmethod
    def _build_runtime_timestamp() -> str:
        """Build the live transmit timestamp for a packet."""
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    def _build_runtime_packet(self, reading: dict[str, Any]) -> dict[str, Any]:
        """Inject the live transmit timestamp into a replay packet."""
        runtime_packet = dict(reading)
        runtime_packet.pop("timestamp", None)
        runtime_packet.pop("source_timestamp", None)
        runtime_packet["timestamp"] = self._build_runtime_timestamp()
        return runtime_packet

    def _send(self, reading: dict[str, Any]) -> bool:
        """POST one reading to the gateway. Returns True on HTTP 200."""
        try:
            runtime_packet = self._build_runtime_packet(reading)
            self._log.info(
                "cgm send id=%d ts=%s glucose=%.1f alert=%s",
                self._index,
                runtime_packet["timestamp"],
                runtime_packet["glucose_mmol"],
                runtime_packet["alert_level"],
            )
            resp = requests.post(
                self._api_endpoint,
                json=runtime_packet,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                self._log.info("cgm accepted status=200")
                return True
            self._log.error("cgm rejected status=%d", resp.status_code)
            return False

        except requests.exceptions.Timeout:
            self._log.error("cgm timeout")
        except requests.exceptions.ConnectionError:
            self._log.error("cgm connection_error endpoint=%s", self._api_endpoint)
        except Exception as exc:
            self._log.error("cgm error=%s", exc)
        return False

    def run(self) -> None:
        """Replay packets at the configured interval until interrupted."""
        self._log.info("cgm loop started")
        while True:
            try:
                reading = self._next_packet()
                if reading is None:
                    self._log.info("cgm completed sent=%d", self._index)
                    break

                self._send(reading)
                time.sleep(self._interval_seconds)
            except KeyboardInterrupt:
                self._log.info("cgm stopped sent=%d", self._index)
                break
            except Exception as exc:
                self._log.error("cgm loop_error=%s", exc)
                time.sleep(self._interval_seconds)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )
    raise SystemExit(
        "Run the CGM via main_cgm_api.py"
    )
