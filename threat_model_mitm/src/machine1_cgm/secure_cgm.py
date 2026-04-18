from __future__ import annotations

from pathlib import Path
from typing import Any

import requests
from requests.exceptions import SSLError

from machine1_cgm.cgm_simulator import CGMSimulator
from security_core.e2e_crypto import encrypt_payload
_BASE = Path(__file__).resolve().parent
_THREAT_MODEL_ROOT = _BASE.parents[1]
_CERTS_DIR = _THREAT_MODEL_ROOT / "certs"


class SecureCGMSimulator(CGMSimulator):
    def __init__(
        self,
        api_endpoint: str,
        packet_file: Path,
        interval_seconds: float = 300.0,
        loop: bool = True,
        mode: str = "secure_cgm",
        certs_dir: Path | None = None,
    ) -> None:
        super().__init__(api_endpoint, packet_file, interval_seconds, loop, mode)
        self._certs_dir = Path(certs_dir) if certs_dir is not None else _CERTS_DIR
        self._ca_bundle = self._certs_dir / "ca.crt"
        self._client_cert = (str(self._certs_dir / "client.crt"), str(self._certs_dir / "client.key"))
        if self._api_endpoint.startswith("http://"):
            self._api_endpoint = "https://" + self._api_endpoint.split("://", 1)[1]

    def _send(self, reading: dict[str, Any]) -> bool:
        try:
            runtime_packet = self._build_runtime_packet(reading)
            body = encrypt_payload(runtime_packet)
            response = requests.post(
                self._api_endpoint,
                json=body,
                timeout=15,
                headers={"Content-Type": "application/json"},
                cert=self._client_cert,
                verify=str(self._ca_bundle),
            )
            if response.status_code == 200:
                self._log.info("secure_cgm accepted status=200")
                return True
            self._log.error("secure_cgm rejected status=%d", response.status_code)
            return False
        except SSLError as exc:
            self._log.error("secure_cgm ssl_error possible_mitm=True detail=%s", exc)
        except requests.exceptions.Timeout:
            self._log.error("secure_cgm timeout")
        except requests.exceptions.ConnectionError:
            self._log.error("secure_cgm connection_error endpoint=%s", self._api_endpoint)
        except Exception as exc:
            self._log.error("secure_cgm error=%s", exc)
        return False
