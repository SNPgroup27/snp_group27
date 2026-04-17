#!/usr/bin/env bash
# SYN cookies — kernel-level mitigation for SYN flood (Linux).
# Run on the *server* VM. Requires: sudo
#
# Defence (recommended default in production): SYN cookies ON
#   ./defence/syn_cookies.sh on
#
# Insecure lab only — to *observe* raw SYN flood behaviour (course slides):
#   ./defence/syn_cookies.sh off
#
set -euo pipefail

case "${1:-status}" in
  on|1|enable)
    sudo sysctl -w net.ipv4.tcp_syncookies=1
    echo "SYN cookies enabled (defence against SYN flood half-open abuse)."
    ;;
  off|0|disable)
    sudo sysctl -w net.ipv4.tcp_syncookies=0
    echo "SYN cookies disabled — lab/demo only; re-enable after testing."
    ;;
  status|"")
    echo "Current net.ipv4.tcp_syncookies:"
    sysctl net.ipv4.tcp_syncookies 2>/dev/null || echo "(sysctl unavailable — are you on Linux?)"
    ;;
  *)
    echo "Usage: $0 [on|off|status]" >&2
    exit 1
    ;;
esac
