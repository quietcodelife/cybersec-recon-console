#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APT_REQ_FILE="$ROOT_DIR/requirements-linux-apt.txt"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "[ERROR] This script currently supports Debian/Ubuntu systems with apt-get." >&2
  exit 1
fi

echo "[*] Installing system packages from: $APT_REQ_FILE"
sudo apt-get update
sudo xargs -a "$APT_REQ_FILE" apt-get install -y

echo "[*] Installing Python dependencies"
bash "$ROOT_DIR/setup_python_env.sh"

echo
echo "[OK] CyberSec Recon Console environment is ready."
