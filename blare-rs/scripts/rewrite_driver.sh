#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <input.sys> <ghidra_cfg.json> <output.sys> <map.json>" >&2
  exit 1
fi

INPUT_SYS="$1"
GHIDRA_CFG="$2"
OUTPUT_SYS="$3"
MAP_JSON="$4"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BLARE_BIN="$ROOT/target/debug/blare"
NORMALIZED_CFG="/tmp/$(basename "$INPUT_SYS").normalized.cfg.json"

if [[ ! -x "$BLARE_BIN" ]]; then
  cargo build -p blare-cli --manifest-path "$ROOT/Cargo.toml"
fi

"$BLARE_BIN" ingest-ghidra \
  --input "$INPUT_SYS" \
  --cfg "$GHIDRA_CFG" \
  --output "$NORMALIZED_CFG" \
  --min-coverage 0.0001

"$BLARE_BIN" rewrite \
  --input "$INPUT_SYS" \
  --cfg "$NORMALIZED_CFG" \
  --output "$OUTPUT_SYS" \
  --map "$MAP_JSON" \
  --profile balanced \
  --strict-unwind \
  --rewrite-policy module

"$BLARE_BIN" verify-unwind --input "$OUTPUT_SYS"

echo "Driver rewrite completed:"
echo "  output=$OUTPUT_SYS"
echo "  map=$MAP_JSON"
