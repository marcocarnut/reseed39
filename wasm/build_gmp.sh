#!/usr/bin/env bash
# Build GMP as a static wasm library for the estimator core.
# librxe depends on GMP (mpz_t everywhere); emscripten has no GMP port, so we
# cross-compile it once. Output: wasm/gmp-wasm/{include,lib/libgmp.a}.
#
# Prereqs: emsdk active (. /root/emsdk/emsdk_env.sh), a native gcc for the
# build machine, curl. Verified working with GMP 6.3.0 on 2026-08-23.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/build"
PREFIX="$HERE/gmp-wasm"
GMP_VER=6.3.0
GMP_SHA256=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898

mkdir -p "$BUILD"
cd "$BUILD"
if [ ! -f gmp.tar.xz ]; then
  curl -sSL -o gmp.tar.xz "https://gmplib.org/download/gmp/gmp-${GMP_VER}.tar.xz"
fi
echo "$GMP_SHA256  gmp.tar.xz" | sha256sum -c -
[ -d "gmp-${GMP_VER}" ] || tar xf gmp.tar.xz
cd "gmp-${GMP_VER}"

. /root/emsdk/emsdk_env.sh >/dev/null 2>&1
make distclean >/dev/null 2>&1 || true
# Force a real cross-build: host=wasm, build=native, native gcc for CC_FOR_BUILD.
emconfigure ./configure \
  --disable-assembly \
  --host=wasm32-unknown-emscripten \
  --build=x86_64-pc-linux-gnu \
  --disable-shared --enable-static \
  --prefix="$PREFIX" \
  CC_FOR_BUILD=/usr/bin/gcc
emmake make -j2
emmake make install
echo "gmp-wasm installed at $PREFIX"
ls -la "$PREFIX/lib/libgmp.a"
