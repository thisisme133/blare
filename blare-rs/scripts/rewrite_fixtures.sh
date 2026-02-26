#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/tests/fixtures/bin"
CFG_DIR="$ROOT/tests/fixtures/cfg"
OUT_DIR="$ROOT/tests/fixtures/out"
MAP_DIR="$ROOT/tests/fixtures/map"

mkdir -p "$OUT_DIR" "$MAP_DIR"

BLARE_BIN="$ROOT/target/debug/blare"

if [[ ! -x "$BLARE_BIN" ]]; then
  cargo build -p blare-cli --manifest-path "$ROOT/Cargo.toml"
fi

if [[ ! -f "$BIN_DIR/fixture_basic.exe" ]]; then
  "$ROOT/scripts/build_fixtures.sh"
fi

for exe in "$BIN_DIR"/*.exe; do
  base="$(basename "$exe" .exe)"
  cfg="$CFG_DIR/$base.json"
  out="$OUT_DIR/$base.rewritten.exe"
  map="$MAP_DIR/$base.map.json"

  "$BLARE_BIN" rewrite \
    --input "$exe" \
    --cfg "$cfg" \
    --output "$out" \
    --map "$map" \
    --profile balanced \
    --strict-unwind \
    --rewrite-policy module

  "$BLARE_BIN" verify-seh --input "$out"
done

echo "Rewrite completed for all fixtures"
