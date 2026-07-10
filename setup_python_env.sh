#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
REQ_FILE="$ROOT_DIR/requirements.txt"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 was not found." >&2
  exit 1
fi

echo "[*] Creating virtualenv: $VENV_DIR"
python3 -m venv "$VENV_DIR"

echo "[*] Installing Python dependencies from: $REQ_FILE"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r "$REQ_FILE"

echo
echo "[OK] Python environment is ready."
echo "[i] Activate (bash/zsh): source .venv/bin/activate"
echo "[i] Activate (fish): source .venv/bin/activate.fish"
echo "[i] Without activation you can run the interpreter directly: .venv/bin/python"
echo "[i] Quick start Linux: bash run_linux.sh"
echo "[i] Quick start macOS: bash run_macos.sh"
