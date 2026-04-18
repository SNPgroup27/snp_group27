"""JSONL-based evidence logger for the attacker node."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import AttackerConfig
from tamper_policy import TamperResult

LOGGER = logging.getLogger(__name__)


def _reset_file(filepath: Path) -> bool:
    """Delete an existing runtime file and report whether it existed."""
    if filepath.exists():
        filepath.unlink()
        return True
    return False


def _utc_now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EvidenceLogger:
    """Write per-packet evidence and a session summary."""

    def __init__(self, config: AttackerConfig) -> None:
        self._cfg = config
        self._packet_map_path = config.log_attack_packet_map
        self._summary_path = config.log_attack_summary
        self._phi_path = config.log_phi_exposure

        for path in (self._packet_map_path, self._phi_path, self._summary_path):
            path.parent.mkdir(parents=True, exist_ok=True)

        packet_map_reset = _reset_file(self._packet_map_path)
        phi_reset = _reset_file(self._phi_path)
        summary_reset = _reset_file(self._summary_path)

        self._packet_map_fh = open(self._packet_map_path, "w", encoding="utf-8")
        self._phi_fh = open(self._phi_path, "w", encoding="utf-8")

        self._start_time: str = _utc_now_iso()
        self._observed: int = 0
        self._modified: int = 0
        self._unchanged: int = 0
        self._dropped: int = 0
        self._low_suppressed: int = 0
        self._high_suppressed: int = 0
        self._normal_unchanged: int = 0
        self._label_only: int = 0
        self._value_only: int = 0

        LOGGER.info(
            "evidence_logger ready packets=%s phi=%s summary=%s",
            self._packet_map_path,
            self._phi_path,
            self._summary_path,
        )
        if packet_map_reset:
            LOGGER.warning("evidence_logger reset existing attack_packet_map.jsonl")
        if phi_reset:
            LOGGER.warning("evidence_logger reset existing phi_exposure.jsonl")
        if summary_reset:
            LOGGER.warning("evidence_logger reset existing attack_summary.json")

    def record(
        self,
        result: TamperResult,
        gateway_ip: str,
        gateway_port: int,
        endpoint: str,
    ) -> None:
        """Record one observed packet."""
        observed_at = _utc_now_iso()
        self._observed += 1

        original_level = result.original_packet.get("alert_level", "")

        if result.action == "modify":
            self._modified += 1
            if original_level == "LOW":
                self._low_suppressed += 1
            elif original_level == "HIGH":
                self._high_suppressed += 1
            if "alert_level" in result.changed_fields and "glucose_mmol" not in result.changed_fields:
                self._label_only += 1
            elif "glucose_mmol" in result.changed_fields and "alert_level" not in result.changed_fields:
                self._value_only += 1
        elif result.action == "drop":
            self._dropped += 1
        else:
            self._unchanged += 1
            if original_level == "NORMAL":
                self._normal_unchanged += 1

        entry: dict[str, Any] = {
            "observed_at": observed_at,
            "action": result.action,
            "attack_event": result.attack_event,
            "impact": result.impact,
            "original_packet": result.original_packet,
            "modified_packet": result.modified_packet,
            "changed_fields": result.changed_fields,
            "gateway_ip": gateway_ip,
            "gateway_port": gateway_port,
            "endpoint": endpoint,
        }
        self._packet_map_fh.write(json.dumps(entry) + "\n")
        self._packet_map_fh.flush()

        self._log_phi(result.original_packet, observed_at)

    def _log_phi(self, packet: dict[str, Any], observed_at: str) -> None:
        """Write one PHI exposure record."""
        phi_entry: dict[str, Any] = {
            "observed_at": observed_at,
            "patient_id": packet.get("patient_id"),
            "device_id": packet.get("device_id"),
            "glucose_mmol": packet.get("glucose_mmol"),
            "alert_level": packet.get("alert_level"),
            "timestamp": packet.get("timestamp"),
            "source": "MITM observed plaintext HTTP",
        }
        self._phi_fh.write(json.dumps(phi_entry) + "\n")
        self._phi_fh.flush()

    def stop(self) -> None:
        """Close the log files and write the summary."""
        self._packet_map_fh.close()
        self._phi_fh.close()

        end_time = _utc_now_iso()
        modification_rate = (
            round(self._modified / self._observed, 4) if self._observed else 0.0
        )

        summary: dict[str, Any] = {
            "start_time": self._start_time,
            "end_time": end_time,
            "observed_packets": self._observed,
            "modified_packets": self._modified,
            "unchanged_packets": self._unchanged,
            "dropped_packets": self._dropped,
            "low_suppressed": self._low_suppressed,
            "high_suppressed": self._high_suppressed,
            "normal_unchanged": self._normal_unchanged,
            "label_only_attempts": self._label_only,
            "value_only_attempts": self._value_only,
            "modification_rate": modification_rate,
            "primary_threat": "LOW and HIGH alert suppression",
            "primary_impact": "time-critical treatment delay",
            "tamper_policy_used": self._cfg.tamper_policy,
        }

        self._summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)

        LOGGER.info(
            "evidence_logger stopped observed=%d modified=%d unchanged=%d dropped=%d",
            self._observed,
            self._modified,
            self._unchanged,
            self._dropped,
        )
        LOGGER.info(
            "evidence_logger low_suppressed=%d high_suppressed=%d modification_rate=%.4f",
            self._low_suppressed,
            self._high_suppressed,
            modification_rate,
        )
        LOGGER.info("evidence_logger summary written path=%s", self._summary_path)
