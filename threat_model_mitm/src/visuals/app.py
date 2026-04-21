"""Visual monitoring app for the CGM MITM coursework demo.

Reads existing runtime outputs from the CGM simulator, API gateway, and
attacker node.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from readers import (
    get_cgm_patient_id,
    get_gateway_patient_ids,
    parse_gateway_alert_log,
    parse_attack_jsonl,
    parse_cgm_log,
    query_gateway_db,
    read_attack_summary,
)

# Repo root is three levels above threat_model_mitm/src/visuals/
_REPO = Path(__file__).resolve().parents[3]
_VISUALS_DIR = Path(__file__).resolve().parent
_VISUALS_CONFIG = _VISUALS_DIR / "config.json"

_CHART_WINDOW = 20

_LEVEL_COLOUR = {
    "LOW": "#FF4B4B",
    "NORMAL": "#21C354",
    "HIGH": "#FF8C00",
}

_DEFAULT_REFRESH_S = 3
_VALID_NODES = ("baseline", "cgm", "gateway", "attacker")

def _node_from_args() -> str:
    """Parse an optional node-specific dashboard target."""
    node = _arg_value("--node", "baseline").lower()
    return node if node in _VALID_NODES else "baseline"


def _cli_warnings() -> list[str]:
    """Return warnings for invalid visual CLI values."""
    warnings: list[str] = []
    node = _arg_value("--node", "baseline").lower()
    if "--mode" in sys.argv:
        warnings.append("Use --node baseline instead of --mode baseline.")
    if node not in _VALID_NODES:
        warnings.append(f"Invalid node '{node}'; using baseline view.")
    return warnings


def _arg_value(flag: str, default: str) -> str:
    """Return the CLI value after a flag, or the default."""
    try:
        idx = sys.argv.index(flag)
        return sys.argv[idx + 1]
    except (ValueError, IndexError):
        return default


def _path_arg(flag: str, default: Path) -> Path:
    """Return a path CLI override, or the default."""
    value = _arg_value(flag, "")
    return Path(value).expanduser().resolve() if value else default


def _load_visual_config() -> dict[str, str]:
    """Load optional visual path defaults from config.json."""
    if not _VISUALS_CONFIG.exists():
        return {}
    try:
        with open(_VISUALS_CONFIG, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _config_path(config: dict[str, str], key: str) -> Path | None:
    """Resolve a visual config path relative to the visuals directory."""
    value = config.get(key)
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (_VISUALS_DIR / path).resolve()
    return path


def _first_existing(candidates: list[Path]) -> Path:
    """Return the first existing candidate, or the first candidate."""
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


_PATH_CONFIG = _load_visual_config()
_CONFIG_CGM_LOG = _config_path(_PATH_CONFIG, "cgm_log")
_CONFIG_GATEWAY_DB = _config_path(_PATH_CONFIG, "gateway_db")
_CONFIG_GATEWAY_ALERT_LOG = _config_path(_PATH_CONFIG, "gateway_alert_log")
_CONFIG_ATTACK_JSONL = _config_path(_PATH_CONFIG, "attack_jsonl")
_CONFIG_ATTACK_SUMMARY = _config_path(_PATH_CONFIG, "attack_summary")

CGM_LOG = _path_arg(
    "--cgm-log",
    _first_existing([
        *([_CONFIG_CGM_LOG] if _CONFIG_CGM_LOG else []),
        _REPO / "threat_model_mitm/src/machine1_cgm/logs/cgm_sent_readings.log",
        _REPO / "machine1_cgm/logs/cgm_sent_readings.log",
    ]),
)
GATEWAY_DB = _path_arg(
    "--gateway-db",
    _first_existing([
        *([_CONFIG_GATEWAY_DB] if _CONFIG_GATEWAY_DB else []),
        _REPO / "threat_model_mitm/data/gateway/hospital.db",
        _REPO / "data/gateway/hospital.db",
    ]),
)
GATEWAY_ALERT_LOG = _path_arg(
    "--gateway-alert-log",
    _first_existing([
        *([_CONFIG_GATEWAY_ALERT_LOG] if _CONFIG_GATEWAY_ALERT_LOG else []),
        _REPO / "threat_model_mitm/src/machine2_gateway/logs/critical_alerts.log",
        _REPO / "machine2_gateway/logs/critical_alerts.log",
    ]),
)
ATTACK_JSONL = _path_arg(
    "--attack-jsonl",
    _first_existing([
        *([_CONFIG_ATTACK_JSONL] if _CONFIG_ATTACK_JSONL else []),
        _REPO / "threat_model_mitm/src/machine3_attacker/logs/attack_packet_map.jsonl",
        _REPO / "machine3_attacker/logs/attack_packet_map.jsonl",
    ]),
)
ATTACK_SUMMARY = _path_arg(
    "--attack-summary",
    _first_existing([
        *([_CONFIG_ATTACK_SUMMARY] if _CONFIG_ATTACK_SUMMARY else []),
        _REPO / "threat_model_mitm/src/machine3_attacker/logs/attack_summary.json",
        _REPO / "machine3_attacker/logs/attack_summary.json",
    ]),
)


def _badge(text: str, colour: str) -> str:
    """Inline HTML coloured bold label."""
    return f'<span style="color:{colour}; font-weight:bold;">{text}</span>'


def _alert_badge(level: str) -> str:
    """Coloured label for a glucose alert level."""
    colour = _LEVEL_COLOUR.get(level, "#888888")
    return _badge(level, colour)


def _collect_patient_ids(
    *,
    include_cgm: bool = True,
    include_gateway: bool = True,
    include_attacker: bool = False,
) -> list[str]:
    """Gather distinct patient IDs from selected data sources."""
    ids: set[str] = set()

    if include_cgm:
        pid = get_cgm_patient_id(CGM_LOG)
        if pid:
            ids.add(pid)

    if include_gateway:
        for pid in get_gateway_patient_ids(GATEWAY_DB):
            ids.add(pid)

    if include_attacker:
        for event in parse_attack_jsonl(ATTACK_JSONL):
            pid = event.get("original_packet", {}).get("patient_id")
            if pid:
                ids.add(str(pid))

    return sorted(ids)


def _count_attack_events(events: list[dict]) -> tuple[int, int, int, int]:
    """Return observed, modified, LOW suppressed, and HIGH suppressed counts."""
    observed = len(events)
    modified = 0
    low_suppressed = 0
    high_suppressed = 0

    for event in events:
        if event.get("action") != "modify":
            continue
        modified += 1
        original_level = event.get("original_packet", {}).get("alert_level")
        if original_level == "LOW":
            low_suppressed += 1
        elif original_level == "HIGH":
            high_suppressed += 1

    return observed, modified, low_suppressed, high_suppressed


def _render_cgm_panel(patient_id: str, file_patient: str | None = None) -> None:
    """CGM simulator panel: what the device sent."""
    st.subheader("CGM Simulator")

    readings = parse_cgm_log(CGM_LOG)
    if file_patient is None:
        file_patient = get_cgm_patient_id(CGM_LOG)

    if not readings:
        st.info("Waiting for CGM log data...")
        return

    if file_patient and patient_id and file_patient != patient_id:
        st.warning(
            f"CGM log is for patient {file_patient} (selected: {patient_id})."
        )

    latest = readings[-1]
    alert = latest["alert_level"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Patient", file_patient or "-")
    c2.metric("Glucose (mmol/L)", f"{latest['glucose_mmol']:.1f}")
    c3.metric("Sent", len(readings))

    accepted = latest.get("accepted")
    if accepted is True:
        status_str = "OK (200)"
    elif accepted is False:
        status_str = "rejected"
    else:
        status_str = "in flight"
    c4.metric("Last status", status_str)

    st.markdown(f"Alert: {_alert_badge(alert)}", unsafe_allow_html=True)
    st.caption(f"Last sent: {latest['timestamp']}")

    window = readings[-_CHART_WINDOW:]
    df = pd.DataFrame(
        {"glucose_mmol": [r["glucose_mmol"] for r in window]},
        index=[r["id"] for r in window],
    )
    st.line_chart(df, color=["#4C78A8"], height=160)


def _render_gateway_panel(patient_id: str) -> None:
    """API gateway panel: what the gateway stored."""
    st.subheader("API Gateway")

    pid_filter = patient_id if patient_id else None
    rows = query_gateway_db(GATEWAY_DB, pid_filter)
    alerts = parse_gateway_alert_log(GATEWAY_ALERT_LOG, pid_filter)

    if not rows:
        st.info("Waiting for gateway DB data...")
    else:
        latest = rows[0]
        dev_alert = latest["device_alert_level"]
        gw_alert = latest["gateway_alert_level"]
        mismatch = bool(latest["alert_mismatch"])

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Patient", latest["patient_id"])
        c2.metric("Glucose (mmol/L)", f"{latest['glucose_mmol']:.1f}")
        c3.metric("Stored rows", len(rows))
        c4.metric("Latency (ms)", f"{latest['latency_ms']:.1f}")

        mc1, mc2, mc3 = st.columns(3)
        mc1.markdown(f"Device alert: {_alert_badge(dev_alert)}", unsafe_allow_html=True)
        mc2.markdown(f"Gateway alert: {_alert_badge(gw_alert)}", unsafe_allow_html=True)
        mismatch_label = _badge("YES", "#FF4B4B") if mismatch else _badge("NO", "#21C354")
        mc3.markdown(f"Mismatch: {mismatch_label}", unsafe_allow_html=True)

        st.caption(f"Last received: {latest['received_at']}")

        window = list(reversed(rows[:_CHART_WINDOW]))
        df = pd.DataFrame(
            {"glucose_mmol": [r["glucose_mmol"] for r in window]},
            index=[r["id"] for r in window],
        )
        st.line_chart(df, color=["#4C78A8"], height=160)

        st.dataframe(
            pd.DataFrame([
                {
                    "id": r["id"],
                    "glucose": f"{r['glucose_mmol']:.1f}",
                    "dev_alert": r["device_alert_level"],
                    "gw_alert": r["gateway_alert_level"],
                    "mismatch": "yes" if r["alert_mismatch"] else "no",
                    "latency_ms": f"{r['latency_ms']:.1f}",
                }
                for r in rows[:5]
            ]),
            width="stretch",
            hide_index=True,
        )

    st.markdown("#### Critical alerts")
    if not alerts:
        st.info("No LOW/HIGH gateway alerts in the current alert log.")
        return

    for alert in alerts:
        level = alert["gateway_alert_level"]
        if level == "LOW":
            treatment = "needs glucose intervention"
        elif level == "HIGH":
            treatment = "needs urgent clinical review"
        else:
            treatment = "has unexpected alert level"
        st.markdown(
            f"Patient `{alert['patient_id']}` {_alert_badge(level)}: "
            f"{alert['glucose_mmol']:.1f} mmol/L, {treatment}.",
            unsafe_allow_html=True,
        )
        st.caption(
            f"row={alert['row_id']} received={alert['received_at']} "
            f"latency_ms={alert['latency_ms']:.1f}"
        )


def _render_attacker_panel(patient_id: str) -> None:
    """Attacker panel: interception, modification, and evidence counters."""
    st.subheader("Attacker Node")

    all_events = parse_attack_jsonl(ATTACK_JSONL)
    summary = read_attack_summary(ATTACK_SUMMARY)

    events = [
        e for e in all_events
        if not patient_id
        or e.get("original_packet", {}).get("patient_id") == patient_id
    ]

    if not events and not summary:
        st.info("Waiting for attacker data...")
        return

    observed, modified, low_sup, high_sup = _count_attack_events(events)
    if not patient_id:
        observed = summary.get("observed_packets", observed)
        modified = summary.get("modified_packets", modified)
        low_sup = summary.get("low_suppressed", low_sup)
        high_sup = summary.get("high_suppressed", high_sup)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Observed", observed)
    c2.metric("Modified", modified)
    c3.metric("LOW suppressed", low_sup)
    c4.metric("HIGH suppressed", high_sup)

    if events:
        latest = events[-1]
        action = latest.get("action", "")
        event_name = latest.get("attack_event", action)
        changed = latest.get("changed_fields", {})

        event_colour = "#FF4B4B" if action in ("modify", "drop") else "#21C354"
        st.markdown(
            f"Latest event: {_badge(event_name, event_colour)}",
            unsafe_allow_html=True,
        )

        if changed:
            parts = [
                f"{field}: {diff.get('before')} -> {diff.get('after')}"
                for field, diff in changed.items()
            ]
            st.caption("Changed: " + " | ".join(parts))

        st.caption(f"Observed at: {latest.get('observed_at', '-')}")

    if events:
        window = events[-_CHART_WINDOW:]
        orig = [
            e.get("original_packet", {}).get("glucose_mmol", 0.0) for e in window
        ]
        mod = [
            e.get("modified_packet", {}).get("glucose_mmol", 0.0) for e in window
        ]
        df = pd.DataFrame(
            {"original": orig, "modified": mod},
            index=list(range(1, len(window) + 1)),
        )
        st.line_chart(df, color=["#4C78A8", "#FF4B4B"], height=180)
        st.caption("Blue = original  |  Red = modified (diverges on tamper)")

node = _node_from_args()
cli_warnings = _cli_warnings()

st.set_page_config(
    page_title="CGM MITM Monitor",
    layout="wide",
    initial_sidebar_state="expanded",
)

with st.sidebar:
    st.title("CGM MITM Monitor")
    for warning in cli_warnings:
        st.warning(warning)
    st.divider()

    if node == "cgm":
        selected = get_cgm_patient_id(CGM_LOG) or ""
        if selected:
            st.caption(f"Patient ID: {selected}")
        else:
            st.info("No CGM patient data found yet.")
    else:
        patient_ids = _collect_patient_ids(
            include_cgm=node == "baseline",
            include_gateway=node in ("baseline", "gateway"),
            include_attacker=node == "attacker",
        )
        if patient_ids:
            selected = st.selectbox("Patient ID", patient_ids)
        else:
            st.info("No patient data found yet.")
            selected = ""

    st.divider()
    refresh_s = st.slider("Refresh (s)", min_value=1, max_value=15, value=_DEFAULT_REFRESH_S)

if node == "cgm":
    mode_label = "CGM Node"
elif node == "gateway":
    mode_label = "Gateway Node"
elif node == "attacker":
    mode_label = "Attacker Node"
else:
    mode_label = "Baseline - CGM + Gateway"
st.title(f"CGM MITM Lab - {mode_label}")

if node == "cgm":
    _render_cgm_panel(selected, selected or None)
elif node == "gateway":
    _render_gateway_panel(selected)
elif node == "attacker":
    _render_attacker_panel(selected)
else:
    col1, col2 = st.columns(2)
    with col1:
        _render_cgm_panel(selected)
    with col2:
        _render_gateway_panel(selected)

time.sleep(refresh_s)
st.rerun()
