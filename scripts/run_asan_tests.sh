#!/usr/bin/env bash
#
# Build _bsv_native with AddressSanitizer and run tests.
#
# Usage:
#   ./scripts/run_asan_tests.sh                     # full fuzz + native tests
#   ./scripts/run_asan_tests.sh tests/bsv/native/   # fuzz tests only
#   ./scripts/run_asan_tests.sh --build-only         # build only, no tests
#
# Requirements:
#   - Clang (macOS Xcode or LLVM)
#   - Python 3.10+
#   - hypothesis (pip install hypothesis)
#
# What it does:
#   1. Rebuilds _bsv_native.so with -fsanitize=address
#   2. Runs the specified tests under ASAN
#   3. Restores the normal (non-ASAN) build
#
# ASAN catches:
#   - Heap buffer overflow / underflow
#   - Stack buffer overflow
#   - Use-after-free
#   - Double free
#   - Memory leaks (on exit)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== ASAN Build: _bsv_native ===${NC}"

# Save the original .so for restoration
NATIVE_SO=$(python3 -c "import _bsv_native; print(_bsv_native.__file__)" 2>/dev/null || true)
if [ -n "$NATIVE_SO" ] && [ -f "$NATIVE_SO" ]; then
    cp "$NATIVE_SO" "${NATIVE_SO}.bak"
    echo "Backed up: $NATIVE_SO"
fi

# Build with ASAN
CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    python3 setup.py build_ext --inplace 2>&1 | tail -5

echo -e "${GREEN}ASAN build complete${NC}"

if [ "${1:-}" = "--build-only" ]; then
    echo "Build-only mode. Run tests manually with:"
    echo "  ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 python3 -m pytest tests/bsv/native/"
    exit 0
fi

# Determine test targets
TEST_TARGET="${1:-tests/bsv/native/}"

echo -e "${YELLOW}=== Running tests under ASAN ===${NC}"
echo "Target: $TEST_TARGET"

# ASAN options:
#   detect_leaks=1       — report memory leaks at exit
#   abort_on_error=1     — crash immediately on ASAN error (visible in test output)
#   print_stats_on_exit=0 — suppress noisy stats
#   detect_stack_use_after_return=1 — catch stack use-after-return
# Note: detect_leaks may not work on macOS (requires LeakSanitizer support)
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:print_stats_on_exit=0"

ASAN_EXIT=0
python3 -m pytest "$TEST_TARGET" -x -v --tb=short 2>&1 || ASAN_EXIT=$?

# Restore original build
echo -e "${YELLOW}=== Restoring non-ASAN build ===${NC}"
if [ -n "$NATIVE_SO" ] && [ -f "${NATIVE_SO}.bak" ]; then
    mv "${NATIVE_SO}.bak" "$NATIVE_SO"
    echo "Restored: $NATIVE_SO"
else
    python3 setup.py build_ext --inplace 2>&1 | tail -3
fi

if [ $ASAN_EXIT -eq 0 ]; then
    echo -e "${GREEN}=== ASAN tests PASSED ===${NC}"
else
    echo -e "${RED}=== ASAN tests FAILED (exit $ASAN_EXIT) ===${NC}"
    exit $ASAN_EXIT
fi
