#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
TARGET="$ROOT_DIR/source_code_linux/main.py"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "[ERROR] Python environment was not found in .venv" >&2
  echo "[i] Run this first: bash setup_python_env.sh" >&2
  exit 1
fi

exec "$PYTHON_BIN" "$TARGET"
