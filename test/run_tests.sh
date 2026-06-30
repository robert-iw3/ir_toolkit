#!/usr/bin/env bash
# Create /tmp/venv, install test deps, and run the full IR-workflow test suite.
# Usage: test/run_tests.sh [extra pytest args]
set -euo pipefail

VENV="/tmp/venv"
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="$(command -v python3 || command -v python)"
[[ -d "$VENV" ]] || "$PY" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$TEST_DIR/requirements.txt"

cd "$TEST_DIR"
exec "$VENV/bin/python" -m pytest "$@"
