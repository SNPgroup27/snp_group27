from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from requests.exceptions import SSLError

_BASE = Path(__file__).resolve().parent
_THREAT_MODEL_ROOT = _BASE.parents[1]
_CERTS_DIR = _THREAT_MODEL_ROOT / "certs"
_SRC = _BASE.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from security_core.e2e_crypto import encrypt_payload

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("secure_cgm")


def _load_packets(packet_file: Path) -> list[dict[str, Any]]:
    with open(packet_file, "r", encoding="utf-8") as fh:
        return json.load(fh)


def run(
    api_endpoint: str,
    packet_file: Path,
    interval_seconds: float = 1.0,
    loop: bool = False,
    certs_dir: Path = _CERTS_DIR,
) -> None:
    ca_bundle = str(certs_dir / "ca.crt")
    client_cert = (str(certs_dir / "client.crt"), str(certs_dir / "client.key"))

    packets = _load_packets(packet_file)
    log.info("[CGM] Loaded %d packets from %s", len(packets), packet_file.name)
    log.info("[CGM] Endpoint: %s", api_endpoint)
    log.info("[CGM] mTLS certs from: %s", certs_dir)

    index = 0
    while True:
        if index >= len(packets):
            if loop:
                index = 0
            else:
                log.info("[CGM] All packets sent - done.")
                break

        reading = dict(packets[index])
        reading.pop("timestamp", None)
        reading["timestamp"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        index += 1

        encrypted_body = encrypt_payload(reading)
        log.info("[CRYPTO] Encrypted packet #%d glucose=%.1f alert=%s",
                 index, reading["glucose_mmol"], reading["alert_level"])

        try:
            resp = requests.post(
                api_endpoint,
                json=encrypted_body,
                timeout=15,
                headers={"Content-Type": "application/json"},
                cert=client_cert,
                verify=ca_bundle,
            )
            if resp.status_code == 200:
                result = resp.json()
                ids = result.get("ids", {})
                log.info("[CGM] Accepted id=%s latency=%.1fms ids_anomaly=%s",
                         result.get("id"), result.get("latency_ms", 0),
                         ids.get("mitm_anomaly", "?"))
            elif resp.status_code == 403:
                log.warning("[REPLAY] Server rejected packet: %s", resp.json())
            else:
                log.error("[CGM] Rejected status=%d body=%s", resp.status_code, resp.text[:200])
        except SSLError as exc:
            log.error("[TLS] SSL ERROR (possible MITM): %s", exc)
        except requests.exceptions.ConnectionError as exc:
            log.error("[CGM] Connection error: %s", exc)
        except Exception as exc:
            log.error("[CGM] Unexpected error: %s", exc)

        time.sleep(interval_seconds)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5051
    endpoint = f"https://127.0.0.1:{port}/api/glucose"
    packet_file = _THREAT_MODEL_ROOT / "data" / "cgm_packets_test" / "test_payload.json"
    run(endpoint, packet_file, interval_seconds=0.5, loop=False)
