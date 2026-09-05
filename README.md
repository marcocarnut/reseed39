# (re)³seed39 — BIP39 / Electrum seed recovery

> *(re)cover expressing what you (re)member with (re)gular expressions*

### ▶ Live demo — **[reseed39.postcogito.org](https://reseed39.postcogito.org)**

Everything runs in *your* browser; nothing is ever sent. For a **real** recovery, run it offline on a machine you trust (see [DEPLOY.md](DEPLOY.md)).

**(re)³seed39** is a **client-side wallet-seed recovery tool** that runs entirely in your browser. You
describe the *shape* of what you half-remember — a mnemonic pattern and/or a passphrase pattern,
written as a compact **regular expression / dictionary** — point it at a **target** you still have
(a Bitcoin **address** or, better, an **xpub**), and it searches the keyspace until it finds the
secret, using your machine's **CPU cores and GPU**. Before it searches, it **estimates the effort**
and tells you honestly whether the job is feasible here, or belongs on bigger hardware, or whether
it is hopeless in terms of time or resources that would need to be expended.

The name plays on **(re)** — for *regular expression* and *recovery* — plus **seed** (the wallet
seed) and **39** (BIP39, and its Electrum cousin); the superscript **³** is the three `(re)` of the
motto. The *regular expression* part is literal: every pattern is enumerated by
**[rxe](https://rxenum.postcogito.org)**, the finite-regex engine at the tool's core. rxe treats a
bounded regex as an integer-indexed **set** (an O(1) bijection between `[0, N)` and the strings it
matches), which is exactly what gives the **exact** keyspace count and makes the search trivially
**shardable** across CPU cores, the GPU, and — for the native CLI — whole machines. The logo styles
it **(re)³seed39**; in running text the name is written `reseed39`.

> **It really searches now, not just estimates.** Earlier versions only *estimated* the effort;
> today the same page enumerates candidates, derives keys, and matches them against your target
> end-to-end — on CPU (multicore Web Workers) and GPU (WebGPU / WGSL) — for the small-to-medium
> jobs a browser can handle. Jobs too big for a browser are what the future **native CLI** (see
> `PLAN.md`) is for.

## Why a *pattern* searcher

BIP39 has **no embedded check**: a mnemonic + passphrase *derives* keys but contains nothing to
test a guess against, so you must supply an external target. And a blind full-charset search is
hopeless. The whole tool works because **you know something** — the first few characters, the rough
length, "a word or two I might have used", the set of words but not their order, one forgotten word.
Encoding that knowledge as a pattern collapses an impossible keyspace into a feasible one. reseed39
is built to help you *express what you remember* and to *stop you from launching a hopeless run*.

## What it does

**Estimate → then search, in one page:**

- **Keyspace cardinality** and a **live dry-run sample** straight from `librxe` (compiled to
  WebAssembly — the *same* enumeration core the native CLI will link, so they can't drift).
- **Auto mode selection by cardinality** — you just write the mnemonic and passphrase patterns;
  whichever side varies is searched. Fixed mnemonic + passphrase pattern → **passphrase** search;
  mnemonic pattern + fixed passphrase → **words** search; both vary → **joint** (the product).
- **BIP39 checksum pre-filter** (toggle) for words/joint mode — only the ~1/16 (12-word) or
  ~1/256 (24-word) checksum-valid candidates pay for the expensive KDF; turn it **off** to also
  find deliberately off-dictionary / custom words.
- **Two seed schemes:** **BIP39** and **Electrum v2** (its distinct KDF salt, seed-version
  validity, and root-based derivation) — both searched, both on CPU and GPU, with joint support.
- **All common script types** from the target: P2PKH `1…` (44), P2SH-P2WPKH `3…` (49),
  P2WPKH `bc1q…` (84), P2TR `bc1p…` (86, taproot). An **xpub** target is the fast lane — a
  32-byte chain-code compare with **no elliptic-curve math in the hot loop at all**.
- **Real in-browser benchmark** of *this* machine (PBKDF2-HMAC-SHA512, the multicore sweep, host
  EC, and the WebGPU seed kernel) → an **honest, calibrated ETA** and a **9-tier verdict** from
  😉 TRIVIAL to 💀 HOPELESS, with concrete narrowing levers when it's poor.
- **Runs the search here:** multicore **CPU** (Web Workers, each with its own librxe core so the
  enumeration itself parallelizes) and **WebGPU** (WGSL PBKDF2-SHA512 seed kernels, incl. a
  per-lane-key kernel for words mode). Pick the engine next to the Search button.
- **Survives long runs:** WebGPU **device-loss self-heal** with an adaptive thermal **cooldown**,
  and **checkpoint/resume** across reloads (on-device only) so a multi-hour job isn't lost.
- **Share & bookmark:** a Share button encodes the full control state into a URL `#hash` (with a
  privacy warning), for building examples or handing a setup to someone; on mobile it opens the
  OS "Share to app" sheet. Per-box tooltips travel in the link too.
- **i18n** — English and Portuguese throughout.

## Privacy — this is a recovery tool for *your own* wallet

- **Nothing ever leaves the browser.** There is no backend; the page makes no network calls with
  your data. A pre-title **banner detects whether you're online** and reminds you that for serious
  recovery you should run it **offline, on a machine you trust**.
- **Your secret fragments stay on-device.** The mnemonic pattern, passphrase, and target are never
  placed in the URL automatically — checkpoints live in `localStorage` only. The **Share** button
  is the one deliberate exception, and it warns you before encoding state into a link.

## Run it

```
# tests (uses emsdk's bundled node):
. /home/mac/emsdk/emsdk_env.sh
node test/test_crypto.js     # BIP39/BIP32 crypto + secp256k1 + address types, byte-exact
node test/test_electrum.js   # Electrum v2 scheme, byte-exact vs Electrum's own vectors
node test/test_p1.js         # librxe->wasm cardinality + unrank
node test/test_p2.js         # estimator model

# the page (static; loopback only — keep it offline for real recovery):
python3 -m http.server 8877 --bind 127.0.0.1
# open http://127.0.0.1:8877/estimator/index.html
```

Future versions will run as a single-page application you can easily add to your amnesiac offline setup.

Pick a **common case** on the left (or start blank), write the **mnemonic** and/or **passphrase**
pattern as an rxe regex, paste your **address or xpub** (the target type and likely derivation are
inferred automatically), **benchmark once**, read the verdict, then **Search** — pause, stop, and
resume as needed. A **Dictionaries** tab registers a `[:name:]` wordlist for use in patterns; the
official BIP39 English list is preloaded as `[:bip39:]` (with `bip39-en`, `en`, `english` aliases),
and the Electrum English list — byte-identical to BIP39's — as `[:electrum-en:]`.

### Pattern quick-reference

| You remember… | Write it as | Notes |
|---|---|---|
| passphrase prefix + a couple of digits | `Correct(horse|Horse)?\d{0,2}` | classic passphrase mode |
| all the words, not the order | `((w1|…|w12) ){{12!?}}` | librxe ordered-permutation; checksum prunes hard |
| one forgotten word | `w1 … [:bip39:] … w12` | ≤2048 candidates × checksum |
| a typo in one word | `… (river|rivet|rover) …` | alternation at that position |
| both fuzzy | mnemonic pattern **and** passphrase pattern | joint = product; keep both tight |

## Layout

```
wasm/        librxe -> WebAssembly core (rxe_wasm.c shim; built rxecore.{js,wasm}; batch-unrank)
estimator/   the app (path kept from the estimator era):
  index.html      the single-page UI (estimate + search, i18n, share, resume)
  model.js        the shared estimator model (cardinality, checksum survival, calibrated ETA/verdict)
  bip39crypto.js  SHA-512 + PBKDF2 + BIP32 + secp256k1 (fixed-base comb) + all address types
  bip39.js        BIP39 checksum validator + fast SHA-256 sieve
  electrum.js     Electrum v2 seed scheme (KDF salt, seed-version, root derivation)
  gpucrack.js     WebGPU driver: seed kernels, device-loss self-heal, search orchestration
  crackworker.js  Web Worker: parallel enumeration sweep + secp256k1 derive/compare
  *.wgsl          WGSL PBKDF2-HMAC-SHA512 kernels (fixed-key + per-lane-key)
  i18n.js         en/pt strings, scales, spoken-count tooltips
data/        official BIP39 wordlist(s)
test/        test_crypto.js · test_electrum.js · test_p1.js · test_p2.js
spike/       benchmarks and experiments
```

## Correctness — THE LAW

Every crypto primitive is gated **byte-exact against a published test vector** (BIP39 Trezor,
BIP32, BIP44/49/84/86 address triples, Electrum's own vectors), and every GPU kernel is gated
**byte-exact against the CPU reference** — never against a sibling model. Cardinality and unrank
come straight from `librxe`, so the estimate and the search can't disagree about what the pattern
generates. See `test/` for the gates and `PLAN.md` for the design and where this is headed.

## Status

Full client-side searcher: BIP39 + Electrum, words / passphrase / joint modes, address + xpub
targets, multicore CPU + WebGPU, calibrated ETA, device-loss self-heal, checkpoint/resume, share
links, en/pt — all browser-verified on real hardware. The **native CLI** (`PLAN.md`) is the heavy
backend for jobs beyond a browser: topmost throughput from high-end GPUs and GPU/CPU clusters.
</content>
