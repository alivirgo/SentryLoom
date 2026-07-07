#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer with sudo so dependencies and resident protection can be installed."
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${SENTRYLOOM_INSTALL_DIR:-/opt/sentryloom}"
DATA_DIR="${SENTRYLOOM_DATA_DIR:-/var/lib/sentryloom}"
NODE_VERSION="${SENTRYLOOM_NODE_VERSION:-24.18.0}"
OPERATING_SYSTEM="$(uname -s)"
MACHINE="$(uname -m)"
RUNTIME_DIR="${INSTALL_DIR}/runtime/node"
DEPENDENCY_REPORT="${INSTALL_DIR}/dependencies.txt"
TEMP_DIR=""

for target in "${INSTALL_DIR}" "${DATA_DIR}"; do
  case "${target}" in
    /*) ;;
    *) echo "Install and data directories must be absolute paths."; exit 1 ;;
  esac
  case "${target}" in
    /|/bin|/etc|/home|/Library|/opt|/private|/System|/usr|/var)
      echo "Refusing unsafe install or data directory: ${target}"
      exit 1
      ;;
  esac
done

cleanup() {
  if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
    rm -rf "${TEMP_DIR}"
  fi
}
trap cleanup EXIT

log() {
  printf '[SentryLoom] %s\n' "$*"
}

install_ubuntu_dependencies() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "This Linux installer currently supports Ubuntu/Debian systems with apt-get."
    exit 1
  fi
  log "Refreshing Ubuntu package metadata"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  log "Installing required runtime and collector packages"
  apt-get install -y --no-install-recommends \
    ca-certificates \
    clamav \
    clamav-freshclam \
    curl \
    iproute2 \
    libnotify-bin \
    nftables \
    procps \
    ufw \
    util-linux \
    xdg-utils \
    xz-utils \
    zenity
}

console_user() {
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    printf '%s' "${SUDO_USER}"
    return
  fi
  stat -f '%Su' /dev/console 2>/dev/null || true
}

install_macos_dependencies() {
  local missing=0
  local command_name
  for command_name in curl tar shasum ps log codesign mount pfctl lsof osascript launchctl; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
      echo "Required macOS command is missing: ${command_name}"
      missing=1
    fi
  done
  if [[ "${missing}" -ne 0 ]]; then
    echo "Install current macOS command-line tools, then rerun this installer."
    exit 1
  fi

  # ClamAV is an optional second-opinion engine. Install it automatically when
  # the administrator already manages this Mac with Homebrew. SentryLoom's
  # built-in scanner, quarantine, telemetry, and monitoring do not require it.
  local brew_bin=""
  local user_name=""
  if [[ -x /opt/homebrew/bin/brew ]]; then
    brew_bin="/opt/homebrew/bin/brew"
  elif [[ -x /usr/local/bin/brew ]]; then
    brew_bin="/usr/local/bin/brew"
  fi
  if ! command -v clamscan >/dev/null 2>&1 && [[ -n "${brew_bin}" ]]; then
    user_name="$(console_user)"
    if [[ -n "${user_name}" && "${user_name}" != "root" ]]; then
      log "Installing optional ClamAV engine with the existing Homebrew installation"
      sudo -u "${user_name}" "${brew_bin}" install clamav
    fi
  fi
  if ! command -v clamscan >/dev/null 2>&1 &&
      [[ ! -x /opt/homebrew/bin/clamscan && ! -x /usr/local/bin/clamscan ]]; then
    log "ClamAV is optional and was not installed because Homebrew is unavailable"
  fi
}

node_platform() {
  case "${OPERATING_SYSTEM}:${MACHINE}" in
    Linux:x86_64|Linux:amd64) printf 'linux-x64' ;;
    Linux:aarch64|Linux:arm64) printf 'linux-arm64' ;;
    Darwin:x86_64|Darwin:amd64) printf 'darwin-x64' ;;
    Darwin:arm64|Darwin:aarch64) printf 'darwin-arm64' ;;
    *)
      echo "Unsupported Node.js platform: ${OPERATING_SYSTEM} ${MACHINE}" >&2
      exit 1
      ;;
  esac
}

verify_sha256() {
  local checksum_file="$1"
  local archive_name="$2"
  local expected
  local actual
  expected="$(awk -v name="${archive_name}" '$2 == name { print $1 }' "${checksum_file}")"
  if [[ ! "${expected}" =~ ^[A-Fa-f0-9]{64}$ ]]; then
    echo "Official Node.js checksum was not found for ${archive_name}."
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${TEMP_DIR}/${archive_name}" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "${TEMP_DIR}/${archive_name}" | awk '{print $1}')"
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    echo "Node.js archive failed SHA-256 verification."
    exit 1
  fi
}

install_private_node() {
  local platform
  local archive_name
  local download_base
  platform="$(node_platform)"
  archive_name="node-v${NODE_VERSION}-${platform}.tar.xz"
  download_base="https://nodejs.org/dist/v${NODE_VERSION}"
  TEMP_DIR="$(mktemp -d)"

  log "Downloading official Node.js v${NODE_VERSION} for ${platform}"
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "${TEMP_DIR}/${archive_name}" \
    "${download_base}/${archive_name}"
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "${TEMP_DIR}/SHASUMS256.txt" \
    "${download_base}/SHASUMS256.txt"
  verify_sha256 "${TEMP_DIR}/SHASUMS256.txt" "${archive_name}"

  rm -rf "${RUNTIME_DIR}"
  install -d -m 0755 "${RUNTIME_DIR}"
  tar -xJf "${TEMP_DIR}/${archive_name}" --strip-components=1 -C "${RUNTIME_DIR}"
  if [[ ! -x "${RUNTIME_DIR}/bin/node" ]]; then
    echo "The private Node.js runtime was not extracted correctly."
    exit 1
  fi
  local installed_major
  installed_major="$("${RUNTIME_DIR}/bin/node" -p 'Number(process.versions.node.split(".")[0])')"
  if [[ "${installed_major}" -ne 24 ]]; then
    echo "The installed private runtime is not Node.js 24."
    exit 1
  fi
}

write_dependency_report() {
  {
    echo "SentryLoom dependency report"
    echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Operating system: ${OPERATING_SYSTEM} ${MACHINE}"
    echo "Private Node.js: $("${RUNTIME_DIR}/bin/node" --version)"
    echo
    echo "Command availability:"
    local command_name
    for command_name in clamscan freshclam ss lsblk systemctl journalctl nft ufw \
      ps df notify-send zenity xdg-open log codesign lsof pfctl osascript open; do
      if command -v "${command_name}" >/dev/null 2>&1; then
        echo "available ${command_name}: $(command -v "${command_name}")"
      elif [[ -x "/opt/homebrew/bin/${command_name}" ]]; then
        echo "available ${command_name}: /opt/homebrew/bin/${command_name}"
      elif [[ -x "/usr/local/bin/${command_name}" ]]; then
        echo "available ${command_name}: /usr/local/bin/${command_name}"
      else
        echo "unavailable ${command_name}"
      fi
    done
  } > "${DEPENDENCY_REPORT}"
  chmod 0644 "${DEPENDENCY_REPORT}"
}

case "${OPERATING_SYSTEM}" in
  Linux) install_ubuntu_dependencies ;;
  Darwin) install_macos_dependencies ;;
  *) echo "Unsupported operating system: ${OPERATING_SYSTEM}"; exit 1 ;;
esac

mkdir -p "${INSTALL_DIR}" "${DATA_DIR}" /usr/local/bin
install_private_node
NODE_BIN="${RUNTIME_DIR}/bin/node"
RUNTIME_PATH="${RUNTIME_DIR}/bin:/opt/homebrew/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

install -d -m 0755 "${INSTALL_DIR}/src" "${INSTALL_DIR}/signatures"
cp -R "${SOURCE_DIR}/src/." "${INSTALL_DIR}/src/"
cp -R "${SOURCE_DIR}/signatures/." "${INSTALL_DIR}/signatures/"
install -m 0644 "${SOURCE_DIR}/package.json" "${INSTALL_DIR}/package.json"
chmod -R go-w "${INSTALL_DIR}"
chmod 0700 "${DATA_DIR}"

cat > /usr/local/bin/sentryloom <<EOF
#!/usr/bin/env bash
export PATH="${RUNTIME_PATH}"
export SENTRYLOOM_DATA_DIR="${DATA_DIR}"
exec "${NODE_BIN}" "${INSTALL_DIR}/src/cli.js" "\$@"
EOF
chmod 0755 /usr/local/bin/sentryloom

case "${OPERATING_SYSTEM}" in
  Linux)
    cat > /etc/systemd/system/sentryloom.service <<EOF
[Unit]
Description=SentryLoom Endpoint Security
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PATH=${RUNTIME_PATH}
Environment=SENTRYLOOM_DATA_DIR=${DATA_DIR}
ExecStart=${NODE_BIN} ${INSTALL_DIR}/src/cli.js protect
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now sentryloom.service
    ;;
  Darwin)
    mkdir -p "${DATA_DIR}/logs"
    cat > /Library/LaunchDaemons/org.sentryloom.endpoint.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.sentryloom.endpoint</string>
  <key>ProgramArguments</key><array>
    <string>${NODE_BIN}</string><string>${INSTALL_DIR}/src/cli.js</string><string>protect</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>${RUNTIME_PATH}</string>
    <key>SENTRYLOOM_DATA_DIR</key><string>${DATA_DIR}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${DATA_DIR}/logs/launchd-output.log</string>
  <key>StandardErrorPath</key><string>${DATA_DIR}/logs/launchd-error.log</string>
</dict></plist>
EOF
    launchctl bootout system/org.sentryloom.endpoint 2>/dev/null || true
    launchctl bootstrap system /Library/LaunchDaemons/org.sentryloom.endpoint.plist
    ;;
esac

write_dependency_report
log "Installed with private Node.js $("${NODE_BIN}" --version)"
log "Dependency report: ${DEPENDENCY_REPORT}"
log "Run the dashboard with: sudo sentryloom dashboard"
