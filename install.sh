#!/usr/bin/env bash
set -euo pipefail

SERVER_URL="http://10.0.0.234:19199"
AGENT_ID=""
PROBE_SOURCE=""
CARRIER="auto"
TOKEN=""
CONFIG_DIR="/etc/cf-anycast-router"
STATE_DIR="/var/lib/cf-anycast-router"
BIN_PATH="/usr/local/bin/cf-router"

usage() {
  cat <<'EOF'
Usage:
  curl -fsSL http://10.0.0.234:19199/install.sh | sudo bash -s -- [options]

Options:
  --server URL       Mother server URL, default: http://10.0.0.234:19199
  --id ID           Agent ID, default: hostname
  --source TEXT     Probe source label, default: Agent ID
  --carrier VALUE   cu, ct, cm, auto, or unknown. default: auto
  --token TOKEN     Optional shared token. Must match CFAR_AGENT_TOKEN on server.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_URL="${2:?missing --server value}"; shift 2 ;;
    --id) AGENT_ID="${2:?missing --id value}"; shift 2 ;;
    --source) PROBE_SOURCE="${2:?missing --source value}"; shift 2 ;;
    --carrier) CARRIER="${2:?missing --carrier value}"; shift 2 ;;
    --token) TOKEN="${2:?missing --token value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$(id -u)" != "0" ]]; then
  echo "Please run as root or with sudo." >&2
  exit 1
fi

if [[ -z "$AGENT_ID" ]]; then
  AGENT_ID="$(hostname -s 2>/dev/null || hostname)"
fi
if [[ -z "$PROBE_SOURCE" ]]; then
  PROBE_SOURCE="$AGENT_ID"
fi

install_packages() {
  if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl ca-certificates
  else
    echo "No supported package manager found. Install curl or wget first." >&2
    exit 1
  fi
}

install_packages

mkdir -p "$CONFIG_DIR" "$STATE_DIR"

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $(uname -m). Supported: amd64, arm64." >&2
    exit 1
    ;;
esac

download_file() {
  local url="$1"
  local output="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 10 "$url" -o "$output"
  else
    wget -O "$output" "$url"
  fi
}

BINARY_NAME="cf-router-linux-$ARCH"
PRIMARY_URL="${SERVER_URL%/}/download/$BINARY_NAME"
FALLBACK_URL="https://raw.githubusercontent.com/kuaichu/CFAnycastRouter/main/dist/$BINARY_NAME"
tmp_binary="$(mktemp -t cfar-agent.XXXXXX)"

if download_file "$PRIMARY_URL" "$tmp_binary"; then
  echo "Downloaded agent binary from mother: $PRIMARY_URL"
else
  echo "Mother binary unavailable; falling back to GitHub: $FALLBACK_URL" >&2
  download_file "$FALLBACK_URL" "$tmp_binary"
fi

install -m 0755 "$tmp_binary" "$BIN_PATH"
rm -f "$tmp_binary"

cat > "$CONFIG_DIR/agent.yaml" <<EOF
probe_source: "$PROBE_SOURCE"
carrier: "$CARRIER"
agent_id: "$AGENT_ID"
server_url: "$SERVER_URL"
agent_token_env: CFAR_AGENT_TOKEN
state_path: "$STATE_DIR/state.json"
seed_ips: []
seed_cidrs: []
EOF

if [[ -n "$TOKEN" ]]; then
  umask 077
  cat > "$CONFIG_DIR/agent.env" <<EOF
CFAR_AGENT_TOKEN=$TOKEN
EOF
else
  touch "$CONFIG_DIR/agent.env"
fi
chmod 600 "$CONFIG_DIR/agent.env"

cat > /etc/systemd/system/cf-anycast-agent.service <<EOF
[Unit]
Description=CF Anycast Router Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-$CONFIG_DIR/agent.env
ExecStart=$BIN_PATH agent $CONFIG_DIR/agent.yaml
Restart=always
RestartSec=10
WorkingDirectory=$STATE_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cf-anycast-agent.service
systemctl restart cf-anycast-agent.service

echo "CF Anycast Router agent installed."
echo "Agent ID: $AGENT_ID"
echo "Server:   $SERVER_URL"
echo "Status:   systemctl status cf-anycast-agent.service"
