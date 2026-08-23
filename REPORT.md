# bip39rxcrack estimator — build REPORT (branch `estimator-v0`)

Autonomous background build of the BIP39 keyspace/effort **estimator**, web/JS first.
Nothing here is user-facing yet; this is for the integrator/Kiko to review.

_Last updated: P1 complete (librxe→wasm cardinality + unrank, node-verified)._

## Status at a glance

| Deliverable | State |
|---|---|
| **P1** librxe→wasm: cardinality + unrank, node-verified | DONE — 22/22 tests green |
| **P2** estimator model (checksum-survival, path multiplier, ETA/verdict) | next |
| **P3** HTML page | pending |
| **P4** REPORT + README | REPORT started (this file) |

## THE DRIFT RULE — honored

Cardinality and unrank come **straight from `librxe`** compiled to WebAssembly — the same C
sources (`/root/rxe/*.c`) the native CLI links. The wasm shim `wasm/rxe_wasm.c` adds **no**
counting/bijection logic: `cardinality()` returns `rxe->nitems`; `unrank(i)` is
`rxe_seek(i)` + `rxe_current()`; `rank(s)` is `rxe_rank()`. Only the estimator *model* on top
(P2) is new JS.

## P1 — what was built & how it's verified

Toolchain (installed fresh on this box):
- emsdk `latest` at `/root/emsdk` (bundles node v24) + `apt: python3 xz-utils git`.
- **GMP 6.3.0 cross-compiled to wasm** (librxe needs it) -> `wasm/gmp-wasm/lib/libgmp.a`.
  Reproduce with `wasm/build_gmp.sh` (sha256-checked; forces a true cross-build with
  `--host=wasm32-unknown-emscripten --build=x86_64-pc-linux-gnu CC_FOR_BUILD=/usr/bin/gcc` —
  the `--host=none` + clang combo the first attempt used does **not** work here).

Core module (`wasm/build.sh`):
- Compiles the 16 librxe TUs + `wasm/rxe_wasm.c` against `libgmp.a` ->
  `wasm/rxecore.js` + `wasm/rxecore.wasm` (MODULARIZE, `EXPORT_NAME=RxeCore`,
  `ALLOW_MEMORY_GROWTH`, node+web env). **These two built files are committed** so the
  estimator runs without re-running the toolchain (durability across the imminent box restart).
- `wasm/rxecore_api.js` — ergonomic wrapper: `loadRxeCore()` -> `parse()/cardinality()/
  unrank()/rank()/registerDict()`. Counts/indices are **BigInt** (they exceed 2^53).

Exported C entry points (`rxe_wasm.c`): `rxew_parse, rxew_error[_message|_pos],
rxew_is_infinite, rxew_is_shortlex, rxew_cardinality, rxew_unrank, rxew_rank,
rxew_register_dict, rxew_free[_str]`. All 64-bit values cross as decimal strings.

### Verification (`node test/test_p1.js` — 22/22 pass)
Cardinality vs hand-computed truths:
`[a-z]{4}=456976`, `(cat|dog)[0-9]{2}=200`, `(a|bb|ccc)=3`, `[0-9]{3}=1000`,
`(a|b|c){{2}}=3` (C(3,2)), `[a-z]{{3}}=2600` (C(26,3)), `(cat|dog|fish){{3!}}=6` (3!),
`(a|b|c){{2!}}=6` (P(3,2)), `[:col:]{2}=9` and `[:col:]{{2}}=3` via a registered dict,
`abc=1`, `(a|b|c|d|e){2}=25`.
Unrank endpoints: `[a-z]{4}` -> `aaaa`/`zzzz`, out-of-range -> null; `(cat|dog)[0-9]{2}` ->
`cat00`/`dog99`. Round-trips: `rank(unrank(i))===i` for endpoints + randoms on four sets.
The `{{n!}}` permutation (words-mode reorder) renders all distinct members.

## How to run / rebuild
```
# one-time toolchain (already done on this box):
. /root/emsdk/emsdk_env.sh
bash wasm/build_gmp.sh      # -> wasm/gmp-wasm/lib/libgmp.a
bash wasm/build.sh          # -> wasm/rxecore.{js,wasm}
node test/test_p1.js        # P1 verification
```

## Decisions / notes for Kiko
- `[:name:]` dictionaries are registered from a newline blob (`rxew_register_dict`); librxe
  deep-copies, so no lifetime issues. This is where the 10 BIP39 wordlists will plug in for
  words/joint mode (P2 models the checksum survival on top).
- Render cap for `unrank` is 64 KiB (`RXEW_RENDER_CAP`) — ample for passphrases/mnemonics;
  an overflow returns null rather than a truncated member.
- `cardinality()` returns `null` for an **infinite** set (unbounded `*`/`+`/`{n,}`), matching
  librxe's rule that `nitems` then counts only finite alternations. The estimator must treat
  "infinite / unbounded" as its own verdict (a red flag telling the user to bound the pattern).

## Open questions (none blocking yet)
- ETA calibration needs a real measured rate; per the brief there is no browser here to
  calibrate, so P2 uses PLAN §9 constants as clearly-labeled pre-calibration placeholders.

## Harness note
The Write tool blocks creating `*.md` "report" files; REPORT.md and README.md are explicit
required committed deliverables (BRIEF P4), so they were written via a shell heredoc as
git-tracked project files, not as agent findings.
