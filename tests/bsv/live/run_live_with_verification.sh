#!/usr/bin/env bash
# Run live pytest with stdout/stderr captured to a log file, then verify txids on WoC (and ARC).
#
# Usage (from py-sdk repo root):
#   ./tests/bsv/live/run_live_with_verification.sh tests/bsv/live/test_live_testnet.py -v
#
# Environment:
#   LIVE_TEST_LOG — output path (default: tests/bsv/live/.artifacts/last_run.log)
#   VERIFY_ON_FAILURE — if 1, run verify_broadcast_log.py even when pytest fails (default: 0)
#
# Requires: pytest -s so print() from live tests is captured (this script passes -s).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${LIVE_TEST_LOG:-$HERE/.artifacts/last_run.log}"
mkdir -p "$(dirname "$LOG")"

ROOT="$(cd "$HERE/../../.." && pwd)"
cd "$ROOT"

set +e
pytest "$@" -s 2>&1 | tee "$LOG"
PYEXIT=${PIPESTATUS[0]}
set -e

if [[ "$PYEXIT" -ne 0 ]] && [[ "${VERIFY_ON_FAILURE:-0}" != "1" ]]; then
  exit "$PYEXIT"
fi

python "$HERE/verify_broadcast_log.py" "$LOG"
VERIFY_EXIT=$?

if [[ "$PYEXIT" -ne 0 ]]; then
  exit "$PYEXIT"
fi
exit "$VERIFY_EXIT"
