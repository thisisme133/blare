#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <input_binary> <output_cfg_json>" >&2
  exit 1
fi

INPUT_BIN="$1"
OUTPUT_CFG="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless}"
GHIDRA_SCRIPT_DIR="${GHIDRA_SCRIPT_DIR:-$WORKSPACE_ROOT/levo-main/ghidra_cfg}"
GHIDRA_PROJECT_ROOT="${GHIDRA_PROJECT_ROOT:-/tmp/ghidra_proj_blare}"

if [[ ! -x "$GHIDRA_HEADLESS" ]]; then
  echo "Ghidra headless not executable: $GHIDRA_HEADLESS" >&2
  exit 1
fi

if [[ ! -f "$GHIDRA_SCRIPT_DIR/ExportCFG.java" ]]; then
  echo "ExportCFG.java not found in script dir: $GHIDRA_SCRIPT_DIR" >&2
  exit 1
fi

mkdir -p "$GHIDRA_PROJECT_ROOT"
mkdir -p "$(dirname "$OUTPUT_CFG")"

base="$(basename "$INPUT_BIN")"
project_name="blare_${base//[^[:alnum:]]/_}_$(date +%s)"

"$GHIDRA_HEADLESS" "$GHIDRA_PROJECT_ROOT" "$project_name" \
  -import "$INPUT_BIN" \
  -postScript ExportCFG.java "$OUTPUT_CFG" \
  -scriptPath "$GHIDRA_SCRIPT_DIR" \
  -deleteProject

echo "Ghidra CFG exported: $OUTPUT_CFG"
