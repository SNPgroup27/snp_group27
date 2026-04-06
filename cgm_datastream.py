"""Fake CGM telemetry stream for the IoMT client.

This file produces randomglucose readings in the JSON shape expected by
``POST /api/cgm/readings`` (``device_id``, ``glucose_mg_dl``, optional ``timestamp``).

TODO: Replace the random number generation below with rows from a kaggle dataset 
"""

from __future__ import annotations

import random
from datetime import datetime, timezone


def random_cgm_reading(device_id: str) -> dict[str, float | str]:
    """Build one CGM-style payload for the simulated datacenter API."""
    return {
        "device_id": device_id,
        "glucose_mg_dl": round(random.uniform(70, 180), 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
