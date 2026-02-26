#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/tests/fixtures/bin"
OUT_DIR="$ROOT/tests/fixtures/out"
REPORT_DIR="$ROOT/tests/fixtures/reports"
LLVM_READOBJ="${LLVM_READOBJ:-/opt/homebrew/opt/llvm/bin/llvm-readobj}"

mkdir -p "$REPORT_DIR"

if [[ ! -x "$LLVM_READOBJ" ]]; then
  echo "llvm-readobj not found at $LLVM_READOBJ" >&2
  exit 1
fi

if ! compgen -G "$OUT_DIR/*.rewritten.exe" >/dev/null; then
  "$ROOT/scripts/rewrite_fixtures.sh"
fi

fail() {
  echo "verify_structure.sh: $*" >&2
  exit 1
}

assert_regex() {
  local pattern="$1"
  local file="$2"
  local message="$3"
  if ! rg -q --pcre2 "$pattern" "$file"; then
    fail "$message (pattern=$pattern file=$file)"
  fi
}

for exe in "$BIN_DIR"/*.exe; do
  base="$(basename "$exe" .exe)"
  rewritten="$OUT_DIR/$base.rewritten.exe"
  orig_report="$REPORT_DIR/$base.orig.readobj.txt"
  rew_report="$REPORT_DIR/$base.rewritten.readobj.txt"

  if [[ ! -f "$rewritten" ]]; then
    fail "Missing rewritten binary for fixture '$base': $rewritten"
  fi

  "$LLVM_READOBJ" --file-headers --sections --coff-basereloc --unwind "$exe" >"$orig_report"
  "$LLVM_READOBJ" --file-headers --sections --coff-basereloc --unwind "$rewritten" >"$rew_report"
  echo "Generated $orig_report"
  echo "Generated $rew_report"

  assert_regex "ExceptionTableRVA: 0x[1-9A-Fa-f][0-9A-Fa-f]*" "$rew_report" "ExceptionTableRVA must be non-zero"
  assert_regex "ExceptionTableSize: 0x[1-9A-Fa-f][0-9A-Fa-f]*" "$rew_report" "ExceptionTableSize must be non-zero"
  assert_regex "BaseRelocationTableRVA: 0x[1-9A-Fa-f][0-9A-Fa-f]*" "$rew_report" "BaseRelocationTableRVA must be non-zero"
  assert_regex "BaseRelocationTableSize: 0x[1-9A-Fa-f][0-9A-Fa-f]*" "$rew_report" "BaseRelocationTableSize must be non-zero"
  assert_regex "Name: \\.blrtxt" "$rew_report" "Missing .blrtxt section"
  assert_regex "Name: \\.blrxdt" "$rew_report" "Missing .blrxdt section"
  assert_regex "Name: \\.blrpdt" "$rew_report" "Missing .blrpdt section"
  assert_regex "UnwindInformation \\[" "$rew_report" "UnwindInformation block missing"
  assert_regex "BaseReloc \\[" "$rew_report" "BaseReloc block missing"

  orig_runtime_count="$(grep -c "RuntimeFunction {" "$orig_report" || true)"
  rew_runtime_count="$(grep -c "RuntimeFunction {" "$rew_report" || true)"
  if (( rew_runtime_count < orig_runtime_count )); then
    fail "RuntimeFunction count regressed for $base: original=$orig_runtime_count rewritten=$rew_runtime_count"
  fi

  orig_dir64_count="$(grep -c "Type: DIR64" "$orig_report" || true)"
  rew_dir64_count="$(grep -c "Type: DIR64" "$rew_report" || true)"
  if (( rew_dir64_count < orig_dir64_count )); then
    fail "DIR64 relocation count regressed for $base: original=$orig_dir64_count rewritten=$rew_dir64_count"
  fi
done

echo "Structural verification passed"
