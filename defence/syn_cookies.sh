#!/usr/bin/env bash
# SYN cookies — kernel-level mitigation for SYN flood (Linux).
# Run on the *server* VM. Requires: sudo
#
# Values: 0=off  1=on when backlog full  2=always on
#
set -euo pipefail

case "${1:-status}" in
  on|1|enable)
    sudo sysctl -w net.ipv4.tcp_syncookies=1
    echo "SYN cookies enabled (defence against SYN flood half-open abuse)."
    echo "Verify: cat /proc/sys/net/ipv4/tcp_syncookies  (expect 1 or 2)"
    ;;
  off|0|disable)
    sudo sysctl -w net.ipv4.tcp_syncookies=0
    echo "SYN cookies disabled — lab/demo only; re-enable after testing."
    echo "Verify: cat /proc/sys/net/ipv4/tcp_syncookies  (expect 0)"
    ;;
  status|"")
    echo "Current net.ipv4.tcp_syncookies:"
    sysctl net.ipv4.tcp_syncookies 2>/dev/null || echo "(sysctl unavailable — are you on Linux?)"
    if [ -r /proc/sys/net/ipv4/tcp_syncookies ]; then
      echo "proc: $(cat /proc/sys/net/ipv4/tcp_syncookies)"
    fi
    ;;
  *)
    echo "Usage: $0 [on|off|status]" >&2
    exit 1
    ;;
esac
