#!/usr/bin/env bash
# Build the librxe->wasm estimator core.
#
# Compiles the SAME librxe C sources the native CLI links (from $RXE_DIR),
# plus the thin rxe_wasm.c shim, against a wasm build of GMP, into a single
# MODULARIZEd module (rxecore.js + rxecore.wasm) loadable from node or a page.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RXE_DIR="${RXE_DIR:-/root/rxe}"
GMP="$HERE/gmp-wasm"

# librxe translation units (see rxe/Makefile 'librxe.a' rule).
RXE_SRCS=(rxe.c rxe_alt.c rxe_node.c parse.c bkreftbl.c permute.c repeat.c \
          comb.c policy.c pair.c lens.c dict.c rank.c graph.c foreach.c rxe_lay.c)

SRCS=()
for f in "${RXE_SRCS[@]}"; do SRCS+=("$RXE_DIR/$f"); done
SRCS+=("$HERE/rxe_wasm.c")

EXPORTS='["_rxew_parse","_rxew_error","_rxew_error_message","_rxew_error_pos","_rxew_is_infinite","_rxew_is_shortlex","_rxew_free","_rxew_free_str","_rxew_cardinality","_rxew_unrank","_rxew_unrank_batch","_rxew_rank","_rxew_register_dict","_malloc","_free"]'
RT='["ccall","cwrap","UTF8ToString","stringToUTF8","lengthBytesUTF8"]'

. /root/emsdk/emsdk_env.sh >/dev/null 2>&1

emcc -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
    -I"$RXE_DIR" -I"$GMP/include" \
    "${SRCS[@]}" "$GMP/lib/libgmp.a" \
    -o "$HERE/rxecore.js" \
    -sMODULARIZE=1 -sEXPORT_NAME=RxeCore \
    -sALLOW_MEMORY_GROWTH=1 \
    -sEXPORTED_FUNCTIONS="$EXPORTS" \
    -sEXPORTED_RUNTIME_METHODS="$RT" \
    -sENVIRONMENT=node,web \
    -sEXPORT_ES6=0 \
    -sSTACK_SIZE=1048576

echo "built: $HERE/rxecore.js  $HERE/rxecore.wasm"
ls -la "$HERE"/rxecore.*
