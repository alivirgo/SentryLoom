#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this uninstaller with sudo."
  exit 1
fi

INSTALL_DIR="${SENTRYLOOM_INSTALL_DIR:-/opt/sentryloom}"
DATA_DIR="${SENTRYLOOM_DATA_DIR:-/var/lib/sentryloom}"

for target in "${INSTALL_DIR}" "${DATA_DIR}"; do
  case "${target}" in
    /*) ;;
    *) echo "Install and data directories must be absolute paths."; exit 1 ;;
  esac
  case "${target}" in
    /|/bin|/etc|/home|/Library|/opt|/private|/System|/usr|/var)
      echo "Refusing unsafe removal target: ${target}"
      exit 1
      ;;
  esac
done

case "$(uname -s)" in
  Linux)
    systemctl disable --now sentryloom.service 2>/dev/null || true
    rm -f /etc/systemd/system/sentryloom.service
    systemctl daemon-reload
    ;;
  Darwin)
    launchctl bootout system/org.sentryloom.endpoint 2>/dev/null || true
    rm -f /Library/LaunchDaemons/org.sentryloom.endpoint.plist
    ;;
esac

rm -f /usr/local/bin/sentryloom
rm -rf "${INSTALL_DIR}"
if [[ "${1:-}" == "--purge-data" ]]; then
  rm -rf "${DATA_DIR}"
  echo "SentryLoom and endpoint data removed."
else
  echo "SentryLoom removed. Endpoint data retained at ${DATA_DIR}."
fi
