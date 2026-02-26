#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT/tests/fixtures/src"
BIN_DIR="$ROOT/tests/fixtures/bin"
CFG_DIR="$ROOT/tests/fixtures/cfg"
GHIDRA_EXPORT_SCRIPT="$ROOT/scripts/export_ghidra_cfg.sh"

mkdir -p "$BIN_DIR" "$CFG_DIR"

GCC="${GCC:-/opt/homebrew/bin/x86_64-w64-mingw32-gcc}"
GXX="${GXX:-/opt/homebrew/bin/x86_64-w64-mingw32-g++}"
BLARE_BIN="$ROOT/target/debug/blare"
USE_REAL_GHIDRA="${USE_REAL_GHIDRA:-auto}"
GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless}"

if [[ ! -x "$GCC" || ! -x "$GXX" ]]; then
  echo "Missing MinGW toolchain: GCC=$GCC GXX=$GXX" >&2
  exit 1
fi

USE_GHIDRA=0
if [[ "$USE_REAL_GHIDRA" == "1" ]]; then
  USE_GHIDRA=1
elif [[ "$USE_REAL_GHIDRA" == "auto" && -x "$GHIDRA_HEADLESS" ]]; then
  USE_GHIDRA=1
fi

cargo build -p blare-cli --manifest-path "$ROOT/Cargo.toml"

"$GCC" -O2 -g -fexceptions "$SRC_DIR/fixture_basic.c" -o "$BIN_DIR/fixture_basic.exe"
"$GXX" -O2 -g -fexceptions -static -static-libgcc -static-libstdc++ "$SRC_DIR/fixture_cpp_eh.cpp" -o "$BIN_DIR/fixture_cpp_eh.exe"
"$GCC" -O2 -g -fexceptions "$SRC_DIR/fixture_reloc.c" -o "$BIN_DIR/fixture_reloc.exe"
"$GCC" -O2 -g -fexceptions "$SRC_DIR/fixture_jump_table.c" -o "$BIN_DIR/fixture_jump_table.exe"
"$GXX" -O2 -g -fexceptions -static -static-libgcc -static-libstdc++ "$SRC_DIR/fixture_unwind_chain.cpp" -o "$BIN_DIR/fixture_unwind_chain.exe"

if ! "$GCC" -O2 -g -fexceptions -fms-extensions "$SRC_DIR/fixture_seh.c" -o "$BIN_DIR/fixture_seh.exe"; then
  echo "SEH __try/__except unsupported by this compiler, using fallback top-level SEH fixture." >&2
  "$GCC" -O2 -g -fexceptions "$SRC_DIR/fixture_seh_fallback.c" -o "$BIN_DIR/fixture_seh.exe"
fi

for exe in "$BIN_DIR"/*.exe; do
  base="$(basename "$exe" .exe)"
  cfg_out="$CFG_DIR/$base.json"
  if [[ "$USE_GHIDRA" -eq 1 ]]; then
    ghidra_cfg="$CFG_DIR/$base.ghidra.json"
    "$GHIDRA_EXPORT_SCRIPT" "$exe" "$ghidra_cfg"
    "$BLARE_BIN" ingest-ghidra --input "$exe" --cfg "$ghidra_cfg" --output "$cfg_out" --min-coverage 0.0001
  else
    if [[ "$USE_REAL_GHIDRA" == "1" ]]; then
      echo "USE_REAL_GHIDRA=1 but GHIDRA_HEADLESS is not executable: $GHIDRA_HEADLESS" >&2
      exit 1
    fi
    tmp_cfg="$CFG_DIR/$base.seed.json"
    "$BLARE_BIN" seed-cfg --input "$exe" --output "$tmp_cfg"
    "$BLARE_BIN" ingest-ghidra --input "$exe" --cfg "$tmp_cfg" --output "$cfg_out" --min-coverage 0.0001
    rm -f "$tmp_cfg"
  fi
done

echo "Fixtures built in $BIN_DIR and cfg files generated in $CFG_DIR"
