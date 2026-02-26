#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/tests/fixtures/bin"
OUT_DIR="$ROOT/tests/fixtures/out"
LOG_DIR="$ROOT/tests/fixtures/logs"

mkdir -p "$LOG_DIR"

WINE_BIN="${WINE_BIN:-/Users/ordi/Downloads/lift/binary_rewriter/tools/wine/Wine Stable.app/Contents/Resources/wine/lib/wine/x86_64-unix/wine}"
WINEPREFIX_PATH="${WINEPREFIX_PATH:-/Users/ordi/Downloads/lift/binary_rewriter/.wineprefix}"

if [[ ! -x "$WINE_BIN" ]]; then
  echo "Wine binary not found: $WINE_BIN" >&2
  exit 1
fi

for orig in "$BIN_DIR"/*.exe; do
  base="$(basename "$orig" .exe)"
  rew="$OUT_DIR/$base.rewritten.exe"
  if [[ ! -f "$rew" ]]; then
    echo "Missing rewritten binary for $base, run scripts/rewrite_fixtures.sh first" >&2
    exit 1
  fi

  olog="$LOG_DIR/$base.orig.log"
  rlog="$LOG_DIR/$base.rew.log"

  set +e
  WINEPREFIX="$WINEPREFIX_PATH" WINEDEBUG=-all "$WINE_BIN" "$orig" >"$olog" 2>&1
  ocode=$?
  WINEPREFIX="$WINEPREFIX_PATH" WINEDEBUG=-all "$WINE_BIN" "$rew" >"$rlog" 2>&1
  rcode=$?
  set -e

  echo "[$base] orig_exit=$ocode rew_exit=$rcode"
  if [[ "$ocode" -ne "$rcode" ]]; then
    echo "Exit code mismatch for $base" >&2
    exit 1
  fi

  if ! diff -u "$olog" "$rlog" >"$LOG_DIR/$base.diff"; then
    echo "Output mismatch for $base, see $LOG_DIR/$base.diff" >&2
    exit 1
  fi

done

echo "Wine behavioral comparison succeeded for all fixtures"
