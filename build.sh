#!/usr/bin/env bash
#
# Build the fuzz target with AddressSanitizer + libFuzzer.
#
# Usage:
#   ./build.sh            # build the vulnerable parser (src/kvparse.c)
#   ./build.sh fixed      # build the patched parser  (src/kvparse_fixed.c)
#
# OSS-Fuzz sets $CC, $CFLAGS and $LIB_FUZZING_ENGINE in its build
# environment; we fall back to sensible local defaults so the same script
# works on your machine and in an OSS-Fuzz-style container.
set -euo pipefail

CC="${CC:-clang}"
# -fsanitize=fuzzer gives us libFuzzer; address catches the OOB read.
CFLAGS="${CFLAGS:--g -O1 -fno-omit-frame-pointer -fsanitize=address,fuzzer}"

SRC="src/kvparse.c"
OUT="kvparse_fuzzer"
if [[ "${1:-}" == "fixed" ]]; then
    SRC="src/kvparse_fixed.c"
    OUT="kvparse_fuzzer_fixed"
fi

echo "Compiling $SRC -> $OUT"
$CC $CFLAGS -Isrc "$SRC" fuzz/kvparse_fuzz.c -o "$OUT"
echo "Built ./$OUT"
