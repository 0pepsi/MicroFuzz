#!/bin/bash
#
# build.sh — Build the mqjs-fuzz custom fuzzer
#
# Usage:
#   ./build.sh              # Normal build (no sanitizers)
#   ./build.sh asan         # Build with AddressSanitizer
#   ./build.sh ubsan        # Build with UndefinedBehaviorSanitizer
#   ./build.sh asan+ubsan   # Build with both
#   ./build.sh debug        # Debug build with -O0
#
set -e

SRCDIR="$(cd ../../ && pwd)"
BUILDDIR="$(pwd)/build"
FUZZDIR="$(pwd)"

CC="${CC:-gcc}"
CFLAGS_BASE="-Wall -g -D_GNU_SOURCE -fno-math-errno -fno-trapping-math -DMQJS_COVERAGE"
LDFLAGS_BASE="-g -lm"
OPT="-O2"
MODE="${1:-release}"
SANITIZER_FLAGS=""
SANITIZER_LDFLAGS=""

case "$MODE" in
    asan)
        echo "[*] Building with AddressSanitizer"
        SANITIZER_FLAGS="-fsanitize=address -fno-omit-frame-pointer -DUSE_ASAN"
        SANITIZER_LDFLAGS="-fsanitize=address"
        OPT="-O1"
        ;;
    ubsan)
        echo "[*] Building with UndefinedBehaviorSanitizer"
        SANITIZER_FLAGS="-fsanitize=undefined -fno-sanitize-recover=all -DUSE_UBSAN"
        SANITIZER_LDFLAGS="-fsanitize=undefined"
        OPT="-O1"
        ;;
    asan+ubsan|ubsan+asan|both)
        echo "[*] Building with ASAN + UBSAN"
        SANITIZER_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -DUSE_ASAN -DUSE_UBSAN"
        SANITIZER_LDFLAGS="-fsanitize=address,undefined"
        OPT="-O1"
        ;;
    debug)
        echo "[*] Debug build"
        OPT="-O0"
        ;;
    release)
        echo "[*] Release build"
        ;;
    *)
        echo "Usage: $0 [release|asan|ubsan|asan+ubsan|debug]"
        exit 1
        ;;
esac

CFLAGS="${CFLAGS_BASE} ${OPT} ${SANITIZER_FLAGS}"
LDFLAGS="${LDFLAGS_BASE} ${SANITIZER_LDFLAGS}"

mkdir -p "$BUILDDIR"

echo "[*] Source dir: $SRCDIR"
echo "[*] Build dir:  $BUILDDIR"
echo "[*] CC:         $CC"
echo "[*] CFLAGS:     $CFLAGS"
echo ""
echo "[1/4] Instrumenting mquickjs.c..."
python3 "$FUZZDIR/patch_engine.py" "$SRCDIR/mquickjs.c" > "$BUILDDIR/mquickjs_inst.c"
echo "[2/4] Copying source files..."
cp "$FUZZDIR/mqjs_cov.h" "$BUILDDIR/"
for f in mquickjs.h mquickjs_priv.h mquickjs_opcode.h mquickjs_atom.h \
         mquickjs_build.h mquickjs_build.c \
         dtoa.c dtoa.h libm.c libm.h cutils.c cutils.h list.h \
         mqjs_stdlib.h softfp_template.h softfp_template_icvt.h; do
    if [ -f "$SRCDIR/$f" ]; then
        cp "$SRCDIR/$f" "$BUILDDIR/"
    fi
done
echo "[3/4] Compiling..."
$CC $CFLAGS -I"$BUILDDIR" -c -o "$BUILDDIR/mquickjs.o" "$BUILDDIR/mquickjs_inst.c"
$CC $CFLAGS -I"$BUILDDIR" -c -o "$BUILDDIR/dtoa.o" "$BUILDDIR/dtoa.c"
$CC $CFLAGS -I"$BUILDDIR" -c -o "$BUILDDIR/libm.o" "$BUILDDIR/libm.c"
$CC $CFLAGS -I"$BUILDDIR" -c -o "$BUILDDIR/cutils.o" "$BUILDDIR/cutils.c"

# Coverage globals (defined in the fuzzer, but we compile separately for clarity)
# Note: __mqjs_cov_map and __mqjs_prev_loc are defined in mqjs_fuzz.c,
# so we don't compile mquickjs_cov.c separately to avoid duplicate symbols.
$CC $CFLAGS -I"$BUILDDIR" -I"$SRCDIR" -c -o "$BUILDDIR/mqjs_fuzz.o" "$FUZZDIR/mqjs_fuzz.c"
echo "[4/4] Linking..."
$CC $LDFLAGS -o "$BUILDDIR/mqjs_fuzz" \
    "$BUILDDIR/mqjs_fuzz.o" \
    "$BUILDDIR/mquickjs.o" \
    "$BUILDDIR/dtoa.o" \
    "$BUILDDIR/libm.o" \
    "$BUILDDIR/cutils.o" \
    -lm

echo ""
echo "[+] Build complete: $BUILDDIR/mqjs_fuzz"
echo ""
echo "Usage:"
echo "  $BUILDDIR/mqjs_fuzz                    # Run with self-generated seeds"
echo "  $BUILDDIR/mqjs_fuzz -i corpus_dir      # Run with external corpus"
echo ""

if [ -n "$SANITIZER_FLAGS" ]; then
    echo "Sanitizer environment variables you may want to set:"
    echo "  export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1"
    echo "  export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"
    echo ""
fi

echo "Outputs:"
echo "  crashes/   — crashing inputs"
echo "  corpus/    — coverage-unique inputs"
