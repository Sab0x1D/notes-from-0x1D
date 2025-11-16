#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

have_python() { command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; }

ensure_python() {
  if have_python; then return 0; fi
  echo "Python 3 not found. Attempting to install..."

  if command -v brew >/dev/null 2>&1; then
    echo "Using Homebrew to install python..."
    brew install python || true
  elif command -v apt-get >/dev/null 2>&1; then
    echo "Using apt to install python3 & venv (may prompt for sudo)..."
    sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip || true
  elif command -v dnf >/dev/null 2>&1; then
    echo "Using dnf to install python3 (may prompt for sudo)..."
    sudo dnf install -y python3 python3-pip || true
  else
    echo "Could not auto-install Python. Please install Python 3.10+ via your package manager."
  fi

  if ! have_python; then
    echo "Python still not available; aborting."
    exit 1
  fi
}

ensure_python

# Resolve python command
if command -v python3 >/dev/null 2>&1; then PY=python3
else PY=python; fi

VENV_PY="./.venv/bin/python"
REQ="./requirements.txt"
REQ_HASH_FILE="./.venv/.req.hash"

# Create venv if missing
if [ ! -x "$VENV_PY" ]; then
  $PY -m venv .venv
fi

"$VENV_PY" -m pip install --upgrade pip wheel setuptools

# Calculate requirements hash
CURR_HASH=$(python - <<'PY'
import hashlib, sys
try:
  with open("requirements.txt","rb") as f: print(hashlib.sha256(f.read()).hexdigest())
except FileNotFoundError:
  print("")
PY
)

PREV_HASH=""
[ -f "$REQ_HASH_FILE" ] && PREV_HASH="$(cat "$REQ_HASH_FILE")"

if [ "$CURR_HASH" != "$PREV_HASH" ]; then
  "$VENV_PY" -m pip install -r "$REQ"
  printf "%s" "$CURR_HASH" > "$REQ_HASH_FILE"
fi

exec "$VENV_PY" ./scan_tui.py
