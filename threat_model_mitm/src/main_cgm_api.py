"""Single entry point for the CGM-to-gateway workflow.

Supports three run modes:
  single   - gateway in a background daemon thread + CGM in foreground (one machine).
  cgm      - CGM simulator only, pointing at a remote gateway.
  gateway  - API gateway only, waiting for remote CGM packets.

Usage:
    python3 threat_model_mitm/src/main_cgm_api.py --mode single
    python3 threat_model_mitm/src/main_cgm_api.py --mode cgm --gateway-ip 192.168.1.1
    python3 threat_model_mitm/src/main_cgm_api.py --mode gateway
    python3 threat_model_mitm/src/main_cgm_api.py --mode single --interval 5
"""

import argparse
import enum
import logging
import threading
import time
from pathlib import Path
from typing import Any

import requests

_SRC = Path(__file__).parent

from machine1_cgm.cgm_simulator import CGMSimulator, load_config as load_cgm_config
from machine2_gateway.api_gateway import APIGateway, load_config as load_gateway_config

CGM_CONFIG_FILE = _SRC / "machine1_cgm" / "config.json"
GATEWAY_CONFIG_FILE = _SRC / "machine2_gateway" / "config.json"

DEFAULT_GATEWAY_HOST = "0.0.0.0"
DEFAULT_GATEWAY_PORT = 5050
DEFAULT_DATABASE_PATH = (_SRC / "machine2_gateway" / "hospital.db").resolve()
DEFAULT_PACKET_FILE = (_SRC / "machine1_cgm" / "packets.json").resolve()
DEFAULT_CGM_INTERVAL_SECONDS = 300.0
DEFAULT_CGM_LOOP = True

_SINGLE_MODE_WARMUP_S: float = 1.5
_HEALTH_RETRIES: int = 10
_HEALTH_RETRY_DELAY_S: float = 0.3


def _load_runtime_config() -> dict[str, Any]:
    """Load node config files and normalise launcher defaults.

    Returns:
        A dict of resolved config-backed defaults for the launcher.
        These values are forwarded into Workflow and can still be overridden
        by CLI arguments where supported.

    Raises:
        RuntimeError: If a required config file is missing or invalid.
    """
    try:
        cgm_config = load_cgm_config(CGM_CONFIG_FILE)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing CGM config file: {CGM_CONFIG_FILE}") from exc

    try:
        gateway_config = load_gateway_config(GATEWAY_CONFIG_FILE)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing gateway config file: {GATEWAY_CONFIG_FILE}") from exc

    try:
        packet_file = Path(cgm_config["packet_file"])
        if not packet_file.is_absolute():
            packet_file = (CGM_CONFIG_FILE.parent / packet_file).resolve()

        database_path = Path(gateway_config.get("database_path", "hospital.db"))
        if not database_path.is_absolute():
            database_path = (GATEWAY_CONFIG_FILE.parent / database_path).resolve()

    except KeyError as exc:
        raise RuntimeError(f"Missing required config key: {exc}") from exc

    return {
        "gateway_host": gateway_config.get("host", DEFAULT_GATEWAY_HOST),
        "gateway_port": int(gateway_config.get("port", DEFAULT_GATEWAY_PORT)),
        "gateway_debug": bool(gateway_config["debug"]),
        "reset_database_on_start": bool(gateway_config.get("reset_database_on_start", True)),
        "database_path": database_path,
        "interval_seconds": float(cgm_config.get("interval_seconds", DEFAULT_CGM_INTERVAL_SECONDS)),
        "loop": bool(cgm_config.get("loop", DEFAULT_CGM_LOOP)),
        "packet_file": packet_file,
    }


class Workflow:
    """Orchestrates the CGM simulator and/or the API gateway."""

    class Mode(enum.Enum):
        SINGLE = "single"
        CGM = "cgm"
        GATEWAY = "gateway"

    def __init__(
        self,
        mode: "Workflow.Mode",
        gateway_ip: str = "127.0.0.1",
        interval_seconds: float = DEFAULT_CGM_INTERVAL_SECONDS,
        loop: bool = DEFAULT_CGM_LOOP,
        gateway_host: str = DEFAULT_GATEWAY_HOST,
        gateway_port: int = DEFAULT_GATEWAY_PORT,
        gateway_debug: bool = False,
        reset_database_on_start: bool = True,
        database_path: Path = DEFAULT_DATABASE_PATH,
        packet_file: Path | None = None,
    ) -> None:
        """
        Args:
            mode:              Workflow mode for runtime context and logging.
            gateway_ip:        IP address of the gateway (loopback for single mode,
                               or the machine IP for split-machine mode).
            interval_seconds:  Packet replay interval passed to the CGM simulator.
            loop:              Whether the CGM replay should repeat after the last packet.
            gateway_host:      Gateway bind host loaded from gateway config.
            gateway_port:      Gateway port loaded from gateway config.
            gateway_debug:     Gateway debug flag loaded from gateway config.
            reset_database_on_start:
                               Whether the gateway should reset its DB on start.
            database_path:     Gateway database path loaded from gateway config.
            packet_file:       CGM packet file path loaded from CGM config.
        """
        self._mode = mode
        self._gateway_ip = gateway_ip
        self._interval_seconds = interval_seconds
        self._loop = loop
        self._gateway_host = gateway_host
        self._gateway_port = gateway_port
        self._gateway_debug = gateway_debug
        self._reset_database_on_start = reset_database_on_start
        self._database_path = database_path
        self._packet_file = packet_file or DEFAULT_PACKET_FILE
        self._log = logging.getLogger("main")

    def _build_gateway(self) -> APIGateway:
        return APIGateway(
            host=self._gateway_host,
            port=self._gateway_port,
            db_path=self._database_path,
            reset_database_on_start=self._reset_database_on_start,
            debug=self._gateway_debug,
            mode=self._mode.value,
        )

    def _build_cgm(self) -> CGMSimulator:
        endpoint = f"http://{self._gateway_ip}:{self._gateway_port}/api/glucose"
        return CGMSimulator(
            api_endpoint=endpoint,
            packet_file=self._packet_file,
            interval_seconds=self._interval_seconds,
            loop=self._loop,
            mode=self._mode.value,
        )

    def _wait_for_gateway_ready(self, gateway_ip: str) -> bool:
        """Check that the expected gateway is serving on the configured port."""
        url = f"http://{gateway_ip}:{self._gateway_port}/health"
        for _ in range(_HEALTH_RETRIES):
            try:
                response = requests.get(url, timeout=1)
                if response.status_code == 200:
                    payload = response.json()
                    if payload.get("status") == "ok" and payload.get("service") == "api_gateway":
                        return True
            except requests.RequestException:
                pass
            time.sleep(_HEALTH_RETRY_DELAY_S)
        return False

    def run(self) -> None:
        """Start the workflow for the configured mode."""
        if self._mode is Workflow.Mode.GATEWAY:
            self._log.info("main mode=gateway")
            self._build_gateway().run()

        elif self._mode is Workflow.Mode.CGM:
            self._log.info("main mode=cgm gateway=%s:%d", self._gateway_ip, self._gateway_port)
            self._build_cgm().run()

        elif self._mode is Workflow.Mode.SINGLE:
            self._log.info("main mode=single")
            gateway = self._build_gateway()

            gw_thread = threading.Thread(
                target=gateway.run,
                name="gateway",
                daemon=True,   # exits automatically when the main thread ends
            )
            gw_thread.start()
            self._log.info("main gateway_start wait=%.1fs", _SINGLE_MODE_WARMUP_S)
            time.sleep(_SINGLE_MODE_WARMUP_S)

            if not self._wait_for_gateway_ready("127.0.0.1"):
                raise RuntimeError(
                    f"Gateway did not become ready on 127.0.0.1:{self._gateway_port}. "
                    "Check for a port conflict or startup failure."
                )

            # CGM runs in the main thread; KeyboardInterrupt stops everything.
            self._build_cgm().run()


def _parse_args(runtime_config: dict[str, Any]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CGM MITM lab - run normal or split workflow.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 threat_model_mitm/src/main_cgm_api.py --mode single\n"
            "  python3 threat_model_mitm/src/main_cgm_api.py --mode cgm --gateway-ip 192.168.1.1\n"
            "  python3 threat_model_mitm/src/main_cgm_api.py --mode gateway\n"
            "  python3 threat_model_mitm/src/main_cgm_api.py --mode single --interval 5\n"
            "  python3 threat_model_mitm/src/main_cgm_api.py --mode single --interval 0.1\n"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=[m.value for m in Workflow.Mode],
        default=Workflow.Mode.SINGLE.value,
        help="Run mode: single | cgm | gateway  (default: single)",
    )
    parser.add_argument(
        "--gateway-ip",
        default=None,
        help=(
            "IP address of the gateway. "
            "Required in cgm mode and ignored in single mode."
        ),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=runtime_config["interval_seconds"],
        help=f"Seconds between CGM packets (default: {runtime_config['interval_seconds']})",
    )
    parser.add_argument(
        "--loop",
        dest="loop",
        action="store_true",
        default=runtime_config["loop"],
        help=f"Replay packets continuously after the final packet (default: {runtime_config['loop']})",
    )
    parser.add_argument(
        "--no-loop",
        dest="loop",
        action="store_false",
        help="Stop after one pass through the packet file",
    )
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )

    try:
        runtime_config = _load_runtime_config()
    except RuntimeError as exc:
        raise SystemExit(f"Launcher configuration error: {exc}") from exc
    args = _parse_args(runtime_config)
    mode = Workflow.Mode(args.mode)

    if args.gateway_ip:
        gw_ip = args.gateway_ip
    elif mode is Workflow.Mode.CGM:
        raise SystemExit("--gateway-ip is required in cgm mode")
    else:
        gw_ip = "127.0.0.1"

    workflow = Workflow(
        mode=mode,
        gateway_ip=gw_ip,
        interval_seconds=args.interval,
        loop=args.loop,
        gateway_host=runtime_config["gateway_host"],
        gateway_port=runtime_config["gateway_port"],
        gateway_debug=runtime_config["gateway_debug"],
        reset_database_on_start=runtime_config["reset_database_on_start"],
        database_path=runtime_config["database_path"],
        packet_file=runtime_config["packet_file"],
    )
    workflow.run()
