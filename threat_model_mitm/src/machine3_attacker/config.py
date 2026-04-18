"""Configuration loader for the attacker node."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

_BASE = Path(__file__).parent
DEFAULT_CONFIG_FILE = _BASE / "config.json"

LOGGER = logging.getLogger(__name__)

_REQUIRED_TOP = (
    "cgm_ip",
    "gateway_ip",
    "gateway_port",
    "gateway_endpoint",
    "network_interface",
    "transparent_proxy_port",
    "enable_ip_forwarding",
    "enable_arp_spoofing",
    "logs",
    "tamper_policy",
)
_REQUIRED_LOGS = ("attack_packet_map", "attack_summary", "phi_exposure")


class AttackerConfig:
    """Load config.json and expose typed properties."""

    def __init__(self, config_path: Path = DEFAULT_CONFIG_FILE) -> None:
        self._config_path = config_path
        self._raw: dict[str, Any] = self._load_and_validate(config_path)
        self._base_dir = config_path.parent

    @staticmethod
    def _load_and_validate(config_path: Path) -> dict[str, Any]:
        """Load the config file and check required keys."""
        with open(config_path, "r", encoding="utf-8") as fh:
            raw: dict[str, Any] = json.load(fh)

        missing = [k for k in _REQUIRED_TOP if k not in raw]
        if missing:
            raise ValueError(f"Config missing required keys: {missing}")

        missing_logs = [k for k in _REQUIRED_LOGS if k not in raw.get("logs", {})]
        if missing_logs:
            raise ValueError(f"Config logs section missing keys: {missing_logs}")

        return raw

    def _resolve_log(self, key: str) -> Path:
        """Resolve a configured log path."""
        p = Path(self._raw["logs"][key])
        if not p.is_absolute():
            return (self._base_dir / p).resolve()
        return p

    @property
    def raw(self) -> dict[str, Any]:
        """Return a copy of the raw config."""
        return dict(self._raw)

    @staticmethod
    def _parse_cli_value(raw_value: str) -> Any:
        """Parse a CLI config value, falling back to plain string."""
        try:
            return json.loads(raw_value)
        except json.JSONDecodeError:
            return raw_value

    def update_field(self, dotted_key: str, raw_value: str) -> None:
        """Update one config field using dotted-key notation."""
        keys = dotted_key.split(".")
        if not all(keys):
            raise ValueError(f"Invalid config key: {dotted_key}")

        current: dict[str, Any] = self._raw
        for key in keys[:-1]:
            next_value = current.get(key)
            if not isinstance(next_value, dict):
                raise ValueError(f"Config path not found: {dotted_key}")
            current = next_value

        current[keys[-1]] = self._parse_cli_value(raw_value)

    def save(self) -> None:
        """Write the current config back to disk."""
        with open(self._config_path, "w", encoding="utf-8") as fh:
            json.dump(self._raw, fh, indent=2)
            fh.write("\n")

    @property
    def cgm_ip(self) -> str:
        """IP address of the CGM simulator node."""
        return str(self._raw["cgm_ip"])

    @property
    def gateway_ip(self) -> str:
        """IP address of the API gateway node."""
        return str(self._raw["gateway_ip"])

    @property
    def gateway_port(self) -> int:
        """TCP port the gateway listens on."""
        return int(self._raw["gateway_port"])

    @property
    def gateway_endpoint(self) -> str:
        """HTTP endpoint path for glucose readings."""
        return str(self._raw["gateway_endpoint"])

    @property
    def network_interface(self) -> str:
        """Network interface used for ARP spoofing and sniffing."""
        return str(self._raw["network_interface"])

    @property
    def transparent_proxy_port(self) -> int:
        """Local port the transparent proxy listens on."""
        return int(self._raw["transparent_proxy_port"])

    @property
    def enable_ip_forwarding(self) -> bool:
        """Whether to enable kernel IP forwarding on start."""
        return bool(self._raw["enable_ip_forwarding"])

    @property
    def enable_arp_spoofing(self) -> bool:
        """Whether to run bidirectional ARP spoofing on start."""
        return bool(self._raw["enable_arp_spoofing"])

    @property
    def tamper_policy(self) -> dict[str, Any]:
        """Raw tamper policy dict keyed by alert level."""
        return dict(self._raw["tamper_policy"])

    @property
    def log_attack_packet_map(self) -> Path:
        """Resolved path for the per-packet JSONL evidence file."""
        return self._resolve_log("attack_packet_map")

    @property
    def log_attack_summary(self) -> Path:
        """Resolved path for the aggregate attack summary JSON file."""
        return self._resolve_log("attack_summary")

    @property
    def log_phi_exposure(self) -> Path:
        """Resolved path for the PHI exposure JSONL file."""
        return self._resolve_log("phi_exposure")
