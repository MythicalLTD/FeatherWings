#!/bin/bash
set -e

CONFIG="/etc/featherpanel/config.yml"
BINARY="/usr/local/bin/featherwings"
SERVICE_UNIT="/lib/systemd/system/featherwings.service"
LEGACY_SERVICE_LINK="/etc/systemd/system/wings.service"
LEGACY_BINARY="/usr/local/bin/wings"

case "${1:-}" in
  configure)
    ;;
  *)
    exit 0
    ;;
esac

mkdir -p /etc/featherpanel
chmod 755 /etc/featherpanel

if [ -x "${BINARY}" ] && [ ! -e "${LEGACY_BINARY}" ]; then
  ln -sf "${BINARY}" "${LEGACY_BINARY}"
fi

if [ -f "${SERVICE_UNIT}" ] && [ ! -e "${LEGACY_SERVICE_LINK}" ]; then
  ln -sf "${SERVICE_UNIT}" "${LEGACY_SERVICE_LINK}"
fi

systemctl daemon-reload || true

if systemctl list-unit-files docker.service >/dev/null 2>&1; then
  systemctl enable docker.service >/dev/null 2>&1 || true
  systemctl start docker.service >/dev/null 2>&1 || true
elif ! command -v docker >/dev/null 2>&1; then
  echo ""
  echo "Warning: Docker is not installed or not available as docker.service." >&2
  echo "Install Docker Engine first: https://docs.docker.com/engine/install/" >&2
  echo ""
fi

if [ -f "${CONFIG}" ]; then
  systemctl enable featherwings.service >/dev/null 2>&1 || true
  if systemctl is-enabled --quiet featherwings.service 2>/dev/null; then
    systemctl restart featherwings.service >/dev/null 2>&1 || systemctl start featherwings.service >/dev/null 2>&1 || true
  else
    systemctl start featherwings.service >/dev/null 2>&1 || true
  fi
  echo "FeatherWings upgraded. Existing configuration preserved and service restarted."
  exit 0
fi

systemctl disable featherwings.service >/dev/null 2>&1 || true

if [ -t 0 ] && [ -t 1 ] && [ "${DEBIAN_FRONTEND:-noninteractive}" != "noninteractive" ]; then
  echo ""
  echo "FeatherWings installed. Docker should already be installed and running."
  echo "Launching the configuration wizard..."
  echo ""
  if "${BINARY}" configure --no-service; then
    systemctl enable featherwings.service >/dev/null 2>&1 || true
    systemctl start featherwings.service >/dev/null 2>&1 || true
    echo ""
    echo "FeatherWings configured and started."
  else
    echo ""
    echo "Configuration was not completed."
    echo "Run 'sudo featherwings configure' when ready, then:"
    echo "  sudo systemctl enable --now featherwings"
    echo ""
  fi
else
  echo ""
  echo "FeatherWings installed successfully."
  echo "Docker Engine (docker-ce) must be installed before starting FeatherWings."
  echo "See: https://docs.docker.com/engine/install/"
  echo ""
  echo "Next steps:"
  echo "  1. sudo featherwings configure"
  echo "  2. sudo systemctl enable --now featherwings"
  echo ""
fi

exit 0
