"""Deterministic tamper policy for intercepted CGM packets."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

LOGGER = logging.getLogger(__name__)

_SUPPORTED_ACTIONS = frozenset(("modify", "forward_log", "drop"))

@dataclass
class TamperResult:
    """Result returned by TamperPolicy.evaluate()."""

    action: str
    original_packet: dict[str, Any]
    modified_packet: dict[str, Any]
    changed_fields: dict[str, dict[str, Any]] = field(default_factory=dict)
    attack_event: str = "none"
    impact: str = "none"
    spoof_success_on_drop: bool = False


class TamperPolicy:
    """Evaluate packets against the configured tamper rules."""

    def __init__(self, policy: dict[str, Any]) -> None:
        self._policy = self._validate(policy)

    @staticmethod
    def _validate(policy: dict[str, Any]) -> dict[str, Any]:
        """Validate the policy configuration."""
        for level, rule in policy.items():
            action = rule.get("action")
            if action not in _SUPPORTED_ACTIONS:
                raise ValueError(
                    f"Unsupported action '{action}' for level '{level}'. "
                    f"Supported: {sorted(_SUPPORTED_ACTIONS)}"
                )
            if action == "modify":
                has_glucose = "replacement_glucose_mmol" in rule
                has_alert = "replacement_alert_level" in rule
                if not has_glucose and not has_alert:
                    raise ValueError(
                        f"Rule for '{level}' action=modify must define "
                        "replacement_glucose_mmol, replacement_alert_level, or both"
                    )
        return policy

    def evaluate(self, packet: dict[str, Any]) -> TamperResult:
        """Apply the tamper policy to one packet."""
        original_level = packet.get("alert_level", "")
        rule = self._policy.get(original_level)

        if rule is None or not rule.get("enabled", True):
            return TamperResult(
                action="no_policy_forward",
                original_packet=dict(packet),
                modified_packet=dict(packet),
                changed_fields={},
                attack_event="no_policy",
                impact="none",
            )

        action = str(rule["action"])

        if action in ("forward_log", "drop"):
            return TamperResult(
                action=action,
                original_packet=dict(packet),
                modified_packet=dict(packet),
                changed_fields={},
                attack_event=str(rule.get("attack_event", action)),
                impact=str(rule.get("impact", "none")),
                spoof_success_on_drop=bool(rule.get("spoof_success_on_drop", False)),
            )

        modified = dict(packet)
        changed_fields: dict[str, dict[str, Any]] = {}
        new_glucose = rule.get("replacement_glucose_mmol")
        new_level = rule.get("replacement_alert_level")

        if new_glucose is not None:
            glucose_value = float(new_glucose)
            if modified.get("glucose_mmol") != glucose_value:
                changed_fields["glucose_mmol"] = {
                    "before": modified.get("glucose_mmol"),
                    "after": glucose_value,
                }
                modified["glucose_mmol"] = glucose_value

        if new_level is not None:
            alert_value = str(new_level)
            if modified.get("alert_level") != alert_value:
                changed_fields["alert_level"] = {
                    "before": modified.get("alert_level"),
                    "after": alert_value,
                }
                modified["alert_level"] = alert_value

        LOGGER.info(
            "tamper level=%s changed=%s event=%s",
            original_level,
            sorted(changed_fields),
            rule.get("attack_event", "modify"),
        )

        return TamperResult(
            action="modify",
            original_packet=dict(packet),
            modified_packet=modified,
            changed_fields=changed_fields,
            attack_event=str(rule.get("attack_event", "modify")),
            impact=str(rule.get("impact", "unknown")),
        )
