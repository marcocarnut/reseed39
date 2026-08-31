# Deploying (re)seed39

The tool is a **single, self-contained HTML file** — publishing (or carrying it
onto an offline machine) is one copy.

## Build the single file

```
# 1) build the librxe wasm core, including the SINGLE_FILE variant the bundler inlines.
#    (One-time toolchain: emsdk + a wasm build of GMP — see REPORT.md / wasm/build_gmp.sh.)
#    On this laptop, reusing jsrxe's GMP-wasm:
RXE_DIR=/home/mac/claude/code/rxe \
GMP_INC=/home/mac/claude/code/jsrxe/build/gmp \
GMP_LIB=/home/mac/claude/code/jsrxe/build/gmp/.libs/libgmp.a \
EMSDK_ENV=/home/mac/emsdk/emsdk_env.sh \
bash wasm/build.sh
#    -> wasm/rxecore.js, wasm/rxecore.wasm, wasm/rxecore-single.js (committed for durability)

# 2) bundle everything into one file:
node tools/bundle.mjs
#    -> dist/reseed39.html   (~1 MB; wasm, wordlist, WGSL shaders, and the crack
#                             Worker are all inlined)
```

`dist/` is git-ignored (regenerate on demand). The wasm core only needs
rebuilding when the C sources or `wasm/build.sh` change — otherwise step 1 can be
skipped and the committed `rxecore-single.js` is reused.

## Publish (served — the normal case)

Copy `dist/reseed39.html` to any static web root (e.g. postcogito.org). It is
fully self-contained: no sibling files, no build step on the server, no backend.
Rename it to `index.html` if you want a bare-directory URL.

## ⚠️ Offline use — serve it locally, don't open from `file://`

The file **works** opened directly from `file://` (double-click), but a `file://`
page has an opaque origin and **cannot start Web Workers**, so the crack drops to
**single-thread**: you lose the multicore CPU sweep and the parallel GPU→secp256k1
derive pool — a large throughput hit on a fast machine.

For full performance on an **air-gapped / amnesiac box (e.g. Tails)**, serve it
locally instead — still fully offline, no network:

```
python3 -m http.server 8877        # in the folder holding reseed39.html
# then open  http://127.0.0.1:8877/reseed39.html
```

Served from `http://localhost`, the inlined Worker starts from its Blob URL and
multicore + the GPU pipeline come back. (The single-file build detects this
automatically — Blob-URL worker when served, graceful single-thread fallback on
`file://`.)

**For a real recovery:** run it offline, on a clean machine you trust, in a safe
unobserved place — the in-app banner says as much. Your mnemonic/passphrase never
leave the page, but only an air-gap makes that certain.

## Sanity check a build

Serve `dist/reseed39.html` locally and confirm: it boots (librxe wasm inlined),
the wordlist loads (a preset shows its candidate count), a small crack finds its
answer on both CPU and GPU, and the console is clean. The gated correctness lives
in `test/` (`node test/test_crypto.js` etc.) against the un-bundled sources.
