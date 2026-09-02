#!/bin/bash
set -e

case "${1:-}" in
  upgrade|install)
    if systemctl is-active --quiet featherwings.service 2>/dev/null; then
      systemctl stop featherwings.service || true
    fi
    if systemctl is-active --quiet wings.service 2>/dev/null; then
      systemctl stop wings.service || true
    fi
    ;;
esac

exit 0
