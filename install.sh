#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/kuaichu/CFAnycastRouter.git"
SERVER_URL="http://10.0.0.234:19199"
AGENT_ID=""
PROBE_SOURCE=""
CARRIER="auto"
TOKEN=""
INSTALL_DIR="/opt/cf-anycast-router"
CONFIG_DIR="/etc/cf-anycast-router"
STATE_DIR="/var/lib/cf-anycast-router"
BIN_PATH="/usr/local/bin/cf-router"

usage() {
  cat <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/kuaichu/CFAnycastRouter/main/install.sh | sudo bash -s -- [options]

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
  if command -v git >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y git golang-go ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y git golang ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y git golang ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache git go ca-certificates
  else
    echo "No supported package manager found. Install git and Go first." >&2
    exit 1
  fi
}

install_packages

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" fetch --all --prune
  git -C "$INSTALL_DIR" reset --hard origin/main
else
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

export GOPROXY="${GOPROXY:-https://goproxy.cn,https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.google.cn}"
echo "Using GOPROXY=$GOPROXY"
echo "Using GOSUMDB=$GOSUMDB"
if ! go mod download; then
  echo "go mod download failed; retrying with GOSUMDB=off" >&2
  GOSUMDB=off go mod download
fi
if ! go build -o "$BIN_PATH" .; then
  echo "go build failed; retrying with GOSUMDB=off" >&2
  GOSUMDB=off go build -o "$BIN_PATH" .
fi

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
WorkingDirectory=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cf-anycast-agent.service

echo "CF Anycast Router agent installed."
echo "Agent ID: $AGENT_ID"
echo "Server:   $SERVER_URL"
echo "Status:   systemctl status cf-anycast-agent.service"
