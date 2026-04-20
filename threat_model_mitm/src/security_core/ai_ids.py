from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
_WINDOW = 10
_DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "gateway" / "hospital.db"


class AnomalyDetector:
    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path is not None else _DEFAULT_DB

    def _load(self) -> pd.DataFrame:
        query = "SELECT id, latency_ms, alert_mismatch, glucose_mmol FROM glucose_readings ORDER BY id ASC"
        with sqlite3.connect(self._db_path) as conn:
            return pd.read_sql_query(query, conn)

    def _rolling_feature_matrix(self, frame: pd.DataFrame) -> np.ndarray:
        rows: list[list[float]] = []
        if len(frame) < _WINDOW:
            return np.asarray(rows, dtype=np.float64)
        for end in range(_WINDOW - 1, len(frame)):
            window = frame.iloc[end - (_WINDOW - 1) : end + 1]
            rows.append(
                [
                    float(window["latency_ms"].mean()),
                    float(window["alert_mismatch"].sum()),
                    float(window["glucose_mmol"].std(ddof=0)),
                ]
            )
        return np.asarray(rows, dtype=np.float64)

    def evaluate_current_state(self) -> dict[str, Any]:
        try:
            frame = self._load()
        except (sqlite3.Error, OSError, ValueError) as exc:
            return {"mitm_anomaly": False, "status": "db_error", "detail": str(exc)}
        if len(frame) < _WINDOW:
            return {"mitm_anomaly": False, "status": "insufficient_window", "packets": int(len(frame))}
        matrix = self._rolling_feature_matrix(frame)
        if len(matrix) < 4:
            return {"mitm_anomaly": False, "status": "insufficient_history", "windows": int(len(matrix))}
        model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42)
        model.fit(matrix[:-1])
        current = matrix[-1:].astype(np.float64)
        pred = int(model.predict(current)[0])
        score = float(model.decision_function(current)[0])
        return {
            "mitm_anomaly": pred == -1,
            "status": "ok",
            "isolation_forest_label": pred,
            "decision_function": score,
            "feature_vector": current[0].tolist(),
        }
