#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT="$HERE/.."
APP="$ROOT/app"
python3 -m venv "$ROOT/.venv"
source "$ROOT/.venv/bin/activate"
pip install --upgrade pip
pip install -r "$APP/requirements.txt"
export APP_SECRET_KEY=${APP_SECRET_KEY:-$(python - <<'PY'
import secrets; print(secrets.token_hex(32))
PY
)}
python "$APP/app.py"
