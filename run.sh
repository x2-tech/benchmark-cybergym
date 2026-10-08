#!/usr/bin/env bash
# Load .env if present, then run the batch evaluation.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

exec .venv/bin/python -m eval.run "$@"
