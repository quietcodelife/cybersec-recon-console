#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BREW_REQ_FILE="$ROOT_DIR/requirements-macos-brew.txt"

if ! command -v brew >/dev/null 2>&1; then
  echo "[ERROR] Homebrew was not found. Install brew and run the script again." >&2
  exit 1
fi

echo "[*] Installing Homebrew packages from: $BREW_REQ_FILE"
while IFS= read -r package || [[ -n "$package" ]]; do
  [[ -z "$package" ]] && continue
  brew install "$package"
done < "$BREW_REQ_FILE"

echo "[*] Installing Python dependencies"
bash "$ROOT_DIR/setup_python_env.sh"

echo
echo "[OK] macOS environment is ready."
