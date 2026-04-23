from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from security_core.ai_ids import AnomalyDetector

_THREAT_MODEL_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DB = _THREAT_MODEL_ROOT / "data" / "gateway" / "hospital.db"
_FALLBACK_DB = Path(__file__).resolve().parents[2] / "data" / "gateway" / "hospital.db"


def _resolve_db() -> Path:
    if _DEFAULT_DB.exists():
        return _DEFAULT_DB
    if _FALLBACK_DB.exists():
        return _FALLBACK_DB
    return _DEFAULT_DB


def _load_latency(db_path: Path) -> pd.DataFrame:
    query = "SELECT id, received_at, latency_ms FROM glucose_readings ORDER BY id DESC LIMIT 200"
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            frame = pd.read_sql_query(query, conn)
    except (sqlite3.Error, OSError, ValueError):
        return pd.DataFrame(columns=["id", "received_at", "latency_ms"])
    if frame.empty:
        return frame
    return frame.sort_values("id")


st.set_page_config(page_title="Medical IoT IDS", layout="wide")
st.title("Clinical gateway monitor (Zero Trust + AI-IDS)")
db_path = _resolve_db()
st.caption(f"Database: `{db_path}`")

latency_df = _load_latency(db_path)
detector = AnomalyDetector(db_path)
ids_state = detector.evaluate_current_state()
if latency_df.empty:
    st.info("No glucose rows yet - start the secure gateway and CGM simulator.")
else:
    st.line_chart(latency_df.set_index("id")["latency_ms"])

if bool(ids_state.get("mitm_anomaly")):
    st.error("MITM anomaly detected.")
else:
    st.success("Secure traffic profile.")
st.json(ids_state)

time.sleep(2)
st.rerun()
