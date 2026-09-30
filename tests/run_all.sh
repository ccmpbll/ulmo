#!/bin/sh
# Run every self-check in tests/. Each file is a standalone script (no pytest),
# so this just loops them and prints one pass/fail summary with a nonzero exit
# if anything failed. CI calls this too, so a failure fails the build.
#
#   ./tests/run_all.sh
#
# Needs Python 3.10+ with requirements.txt installed — the app uses `X | None`
# annotations, which are a runtime TypeError on 3.9. Set PYTHON to point at a
# specific interpreter; otherwise .venv/bin/python is used if it exists.
#
#   PYTHON=/opt/homebrew/bin/python3.12 ./tests/run_all.sh

set -u
cd "$(dirname "$0")/.." || exit 2

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"
  else
    PY="python3"
  fi
fi

if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
  echo "error: need Python 3.10+, got: $("$PY" -V 2>&1)" >&2
  echo "       set PYTHON=/path/to/python3.12 (or create .venv)" >&2
  exit 2
fi

if ! "$PY" -c 'import fastapi, sqlmodel' 2>/dev/null; then
  echo "error: dependencies missing — run:" >&2
  echo "       $PY -m pip install -r requirements.txt" >&2
  exit 2
fi

fail=0
for t in tests/test_*.py; do
  printf '%-40s ' "$t"
  if out=$("$PY" "$t" 2>&1); then
    echo "PASS"
  else
    echo "FAIL"
    printf '%s\n' "$out" | sed 's/^/    /'
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "all self-checks passed"
else
  echo "self-checks FAILED" >&2
fi
exit "$fail"
