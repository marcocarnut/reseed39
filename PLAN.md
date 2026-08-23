# bip39rxcrack — Implementation Plan

> *Cracking hard is alright, but smart is better.*

**Status:** design only. This directory contains **just this plan**. No code yet.
**Audience:** an agent (or human) starting **cold**, in a fresh context window, who has
never seen this project. Read this top to bottom before writing a line of code.
**Author of plan:** carried over from the bip38rxcrack work; cross-checked crypto below.
**Date drafted:** 2026-08-23.

---

## 0. TL;DR — what we're building and why it's different

`bip39rxcrack` recovers a **BIP39 wallet secret you half-remember**, by enumerating a
**regular-expression / dictionary keyspace** (via `librxe`) and running each candidate
through the full BIP39→BIP32→address pipeline until it matches a target you provide.

It is the sibling of **bip38rxcrack** (BIP38 passphrase cracker) and reuses most of its
scaffolding. The crypto, however, is *very* different, and three facts dominate the whole
design:

1. **The KDF is not memory-hard.** BIP39 seed derivation is `PBKDF2-HMAC-SHA512` with
   **2048 iterations** — *not* scrypt. Per candidate that is ~4096 SHA-512 compressions,
   roughly **2–3 orders of magnitude cheaper** than BIP38's `scrypt(16384,8,8)`. So this
   tool is intrinsically **~100–1000× faster** than bip38rxcrack (see §9).

2. **There is NO self-check.** BIP38 keys embed a 4-byte address hash, so bip38rxcrack can
   verify a guess against the key itself. **BIP39 embeds nothing.** A mnemonic+passphrase
   deterministically *produces* keys; there is nothing inside it to test a guess against.
   **Therefore the user MUST supply an external target** — a known **address** or (better)
   an **xpub**. Without a target the tool can only *derive*, not *crack*. This is the single
   biggest structural difference from bip38rxcrack, and it drives the CLI and the verify path.

3. **Two search dimensions, not one.** Besides the regex keyspace, we iterate over
   **derivation paths / script types** (BIP44/49/84/86, Electrum-style, account & address
   indices). The seed is computed **once per candidate** (the expensive part); the path
   fan-out reuses it cheaply. Correct structuring of this fan-out is central to performance.

Three things the user can be searching (the "unknown") — a spectrum that falls out of the
regex enumeration:

- **Passphrase mode (PRIMARY).** The 12/24-word mnemonic is **known and fixed**; the user
  forgot the **BIP39 passphrase** (the "25th word" / Trezor-Ledger passphrase). This is the
  exact analog of what bip38rxcrack does — remember the *shape*, search a regex keyspace.
- **Words mode (SECONDARY).** The passphrase is known/empty; some **mnemonic words** are
  unknown, mis-ordered, or mistyped. Here the **BIP39 checksum** is a powerful pre-filter
  (§7), and `librxe`'s permutation/combination operators shine.
- **Joint mode (LONGSHOT, but it comes for free).** The user remembers **neither** exactly —
  only the *shape* of both the mnemonic and the passphrase. This is the **product** of the
  two keyspaces: for each candidate mnemonic, sweep the whole passphrase keyspace. It follows
  naturally from the enumeration, with three important structural notes (§7.1): the two pieces
  enter the KDF in **different roles** (mnemonic = HMAC *key*, passphrase = *salt*), so it is a
  **nested product of two enumerations, not one flat regex**; the **checksum prunes the words
  dimension first** (16×/256× fewer KDFs); and the **HMAC key-schedule is shared** across the
  entire passphrase sweep of each valid mnemonic. Realistically feasible only when *both*
  shapes are tight — but who knows.

---

## 1. Context you need: `librxe`, the rxe family, and conventions

**`librxe`** is a regex-**enumeration** library (in the sibling `rxe` repo, at
`../rxe`, overridable with `RXE_DIR`). It treats a finite regular expression as a **set**
and provides a **bijection between integers `[0, N)` and the strings of that set** — so it
can `unrank` the *i*-th string in O(1) and `rank` a string back to its index. Kiko's
original design thesis: *the integer bijection and cheap unrank are the killer feature* —
they make **sharding trivial** (`rxe_foreach(from, count)`), which is exactly what powers
multi-threading, GPU batching, double-buffering, and (future) multi-machine work-splitting.
Everything about scaling this tool leans on that.

**The rxe family and its motto** — keep naming/behavior consistent with these:

- **`rxe` / `rxenum` / `rxejit`** — the core library + CLIs. `rxenum` enumerates; `rxejit`
  JIT-compiles a finite regex to C/GPU kernels for brute-force. `rxenum` provides the
  **dictionary mechanism**: a regex can reference `[:name:]` and a *resolver* loads
  `name.dict` (one word per line). The `-D dir` flag adds search directories.
- **`bip38rxcrack`** — sibling repo (`github.com/marcocarnut/bip38rxcrack`), our template.
  CPU + OpenCL + CUDA, ~1 KH/s on an RTX 5090, byte-exact-gated. **Read its source; we fork
  its structure.** It already contains, ready to reuse: base58check, HASH160/RIPEMD-160,
  a gmp-based secp256k1, scrypt (we drop it), the GPU KDF harness (host↔GPU split,
  double-buffer, sharding), `-D` dictionaries, `-p` progress/ETA, env-var conventions,
  the Python **oracle** pattern, and the **byte-exact GPU gating discipline**.
- **`jsrxe`** — the browser/WebGPU incarnation (not needed here, but the family shares
  ideas). Not in scope.

**The motto** — `Cracking hard is alright, but smart is better.` Put it in the banner,
README, and man page, as the siblings do. The whole point of these tools is that the user
*knows something* that collapses an impossible keyspace into a feasible one.

**Consistency rules (do these):**
- Binary name `bip39rxcrack`; man page `bip39rxcrack.1`; env vars prefixed **`RXE39_`**
  (mirror `RXE38_GPU_GAP`, `RXE38_GPU_MONO`, `RXE38_BACKEND`, `RXE38_VERIFY_THREADS`, …).
- Link `librxe` from `../rxe` as an external dep; `RXE_DIR` overrides. Makefile targets
  `make` (CPU) / `make gpu` (+OpenCL) / `make cuda` (+CUDA) / `make test`.
- **THE LAW (inherited):** every GPU kernel result is gated **byte-exact against the CPU
  reference**, and every crypto primitive against a **published test vector**. No GPU
  result is trusted without a byte-exact check vs the CPU oracle. Never gate a backend
  against a sibling model — always against the reference implementation.
- Collaboration model (as in bip38rxcrack): a box-agent builds/measures on real NVIDIA
  hardware (RTX 5090D on GPUhub) via Remote Control; the integrator is correctness
  authority + sole git owner. (Re-establish this only when we actually start building.)

---

## 2. The cryptographic pipeline (the ground truth the code must match)

This is the spec. The Python **oracle** (§13) implements exactly this; the C and every GPU
kernel are gated byte-exact against it.

### 2.1 Normalization — **mandatory, do not punt**
BIP38 used raw UTF-8 bytes. **BIP39 requires Unicode `NFKD` normalization** of *both* the
mnemonic sentence and the passphrase **before** PBKDF2. ASCII is a no-op, but any accented
/ non-Latin passphrase differs if you skip this. Since candidates come from a regex that may
include non-ASCII, we need an NFKD step per candidate (cheap; and a no-op fast path for
pure-ASCII candidates, which we detect once). Pick a small NFKD implementation (bundled
tables) or restrict v1 to a documented ASCII-only mode **with a loud warning** — but the
proper answer is NFKD. Electrum's own scheme normalizes slightly differently (§8, §16).

### 2.2 Mnemonic → 512-bit seed (BIP39)
```
seed = PBKDF2( PRF   = HMAC-SHA512,
               P     = NFKD(mnemonic),
               S     = "mnemonic" || NFKD(passphrase),   // ASCII "mnemonic" + passphrase
               c     = 2048,
               dkLen = 64 )
```
`dkLen=64` is exactly one HMAC-SHA512 block ⇒ only T₁ ⇒ **2048 iterations × 2 SHA-512 =
~4096 compressions** (+2 for HMAC key setup). In passphrase mode the HMAC **key = mnemonic
is fixed**, so the ipad/opad state can be precomputed once and reused across all candidates
(saves 2 of 4096 — negligible, but free). The salt varies per candidate, so the 2048-chain
is redone each time.

### 2.3 Seed → BIP32 master
```
I  = HMAC-SHA512( key = "Bitcoin seed", data = seed )
IL = master private key (must be nonzero and < n; else this seed is invalid)
IR = master chain code
```

### 2.4 BIP32 child derivation (CKDpriv)
`ser32(i)` = big-endian uint32. Hardened iff `i ≥ 0x80000000`.
```
hardened (i ≥ 2^31):  I = HMAC-SHA512( c_par, 0x00 || ser256(k_par) || ser32(i) )     // NO ec mult
normal   (i <  2^31):  I = HMAC-SHA512( c_par, serP(point(k_par)) || ser32(i) )        // needs parent PUBKEY
k_i = (parse256(IL) + k_par) mod n
c_i = IR
```
`serP(point(k))` = 33-byte **compressed** pubkey = one **fixed-base** `k·G` multiply.
Only **normal** (non-hardened) steps need a mult; hardened steps are pure hashing.

**EC-mult accounting for a full path `m/purpose'/coin'/account'/change/index`:**
- 3 hardened steps (`purpose'`,`coin'`,`account'`) → **0 mults**.
- `change` (normal) needs pub(account node) → **1 mult**.
- `index` (normal) needs pub(change node) → **1 mult**.
- address needs pub(index node) → **1 mult** (also completes the last step).
- ⇒ **3 fixed-base mults per address** (fewer with xpub — see §6).

Fixed-base `k·G` is the *fast* kind (precomputed tables; libsecp256k1 does ~50–70K/s/core).

### 2.5 Pubkey → address / output program (script types)
Decode the user's **target once** into `(script_type, program_bytes)`; then per candidate
compute `program_bytes` and `memcmp` — **no per-candidate base58/bech32 encoding**.

| BIP | Path prefix | Script | Program to compare | Address form |
|-----|-------------|--------|--------------------|--------------|
| 44  | `m/44'/0'/a'/c/i` | P2PKH | `HASH160(cpub)` (20B) | base58check v0x00 → `1…` |
| 49  | `m/49'/0'/a'/c/i` | P2SH-P2WPKH | `HASH160(0x0014‖HASH160(cpub))` (20B) | base58check v0x05 → `3…` |
| 84  | `m/84'/0'/a'/c/i` | P2WPKH | `HASH160(cpub)` (20B), witver 0 | bech32, hrp `bc` → `bc1q…` |
| 86  | `m/86'/0'/a'/c/i` | P2TR | x-only **tweaked** output key `Q_x` (32B), witver 1 | bech32m → `bc1p…` |

- **Taproot (86)** costs a little more EC: internal key `P` = x-only cpub; tweak
  `t = tagged_hash("TapTweak", P_x)`; output `Q = P + t·G`; compare `Q_x`. That's **+1 mult
  and a point-add** beyond deriving the pubkey. Need `lift_x` / x-only handling. bech32m,
  not bech32.
- Legacy keys may be **uncompressed** (different HASH160) — modern wallets are compressed.
  Offer a `--uncompressed` toggle for legacy P2PKH; default compressed.
- We need **bech32 + bech32m** encode/decode (bip38rxcrack has only base58check). Add a
  small module. Decoding the target to its witness program is enough; encoding is only for
  pretty-printing the hit.

**Address format → likely purpose** (used to prune the path fan-out, §5): `1…`→44,
`3…`→49, `bc1q…`(len 42)→84, `bc1p…`→86. Not 100% (a `1…` can come from many schemes/paths),
but a strong default.

---

## 3. What the user must provide (and the verify fast-path decision tree)

Because there is **no embedded check** (§0.2), the CLI **requires a target**. Ranked best→worst:

1. **Account-level xpub** (e.g. exported `m/44'/0'/0'` — hardware wallets & Electrum export
   this). **This is the jackpot:** an xpub carries the node's **chain code (32B)** *and*
   pubkey (33B). We derive the **hardened path only** (pure HMAC-SHA512, **zero mults**),
   and the resulting **chain code `IR` compares directly to the xpub's chain code — with no
   secp256k1 at all**. Chain-code match ⇒ near-certain hit; then confirm with the pubkey
   (1 mult) on the survivor. **Consequence: with an account xpub, the entire crack is
   SHA-512-only** — no EC in the hot loop. That is the *ideal GPU workload* (all hashing,
   trivially parallel, no big-int curve math on device). Flag this loudly to users:
   *"have an xpub? this runs an order of magnitude leaner."*
   Path fan-out here is tiny: `{44',49',84',86'} × {account 0'..k'}` — a handful.

2. **Root xpub `m`** (rare): compare master chain code `IR` from the "Bitcoin seed" HMAC —
   cheapest possible, zero derivation, zero mults.

3. **A known address** (the common case): no chain code available, so we must derive to the
   pubkey and build the program (§2.5) → **3 mults per (path,index)** and we must guess
   `change ∈ {0,1}` and `index ∈ [0,gap)`. Bigger fan-out, real EC in the loop.

4. **Several known addresses** (they saved a few): match any — a bit more per-candidate work
   but a much better chance of hitting a low index.

**Rule:** if the user can get their **account xpub**, tell them to use it — it removes
secp256k1 from the hot path and multiplies throughput (§9). Provide clear docs on where
wallets export it.

---

## 4. The two search dimensions and how they compose

```
for each passphrase-candidate p in regex-keyspace (librxe unrank/shard):     # DIM 1 — expensive
    seed = BIP39_seed(mnemonic, p)              # ~4096 SHA-512   <-- the cost
    master = BIP32_master(seed)
    for each (script_type, account, change, index) in path-plan:             # DIM 2 — cheap
        node = derive(master, path)             # few HMAC + 0..3 mults
        if matches(node, target): HIT(p, path)
```

Key structural facts:
- **DIM 1 dominates on CPU** (the KDF). DIM 2 is a few HMACs + a few mults, reusing the one
  seed. So **fan out paths freely on CPU** — it barely moves the needle.
- **On GPU the balance flips.** The KDF is so cheap that DIM 2 (EC + fan-out) can become the
  bottleneck; keep the default fan-out small and, in the address case, consider moving
  secp256k1 onto the GPU (§10). With an **xpub** target there is no EC, so GPU stays ideal
  even with fan-out.
- The **path-plan** is precomputed from user options + target inference (§5). Enumerate it
  once; don't re-parse per candidate.

Words mode inverts the dimensions: DIM 1 becomes the mnemonic enumeration (with a checksum
pre-filter, §7) and the passphrase is fixed; DIM 2 is the same path-plan.

---

## 5. Derivation-path handling (the second dimension, in detail)

The user may know the path exactly, partially, or not at all. Provide:

- `--path "m/84'/0'/0'/0/0"` — exact single path (fastest, honed).
- `--paths bip44,bip49,bip84,bip86` — try these purposes (default = **infer from target
  address format**; if xpub or ambiguous, default to all four).
- `--account A` or `--accounts 0-2` — account index range (default `0`).
- `--change 0` / `--change 0,1` — external/internal chain (default `0`; add `1` if the
  address might be change).
- `--gap N` — address index range `0..N-1` (default **1** for cracking; a real match is
  usually index 0. Raising it multiplies DIM-2 cost).
- **Wallet presets** for non-BIP44 layouts, notably:
  - **Electrum** standard: short paths like `m/0'/0/i` (receive) and `m/0'/1/i` (change).
    (⚠️ Electrum's *own seed phrases are NOT BIP39* — different KDF salt & checksum, §8/§16.
    But a **BIP39 seed used in Electrum** can use Electrum-style *paths*, so we support the
    paths here regardless.)
  - Legacy/`m/0/i`, MultiBit, blockchain.info-era oddities — add as presets over time.
  - `--preset electrum-legacy`, `--preset electrum-segwit`, etc.
- `--path-file` — arbitrary list of path templates with `{account}`, `{change}`, `{index}`.

**Cost of getting this wrong:** each extra (path × account × change × index) is another
DIM-2 iteration per candidate. On CPU cheap; on GPU it can dominate. So: **infer narrowly by
default, let the user widen.** Print the effective path-plan size at startup (part of the
estimate, §9/UI).

---

## 6. Verification, concretely

- **xpub target:** derive hardened path (no mult); compare **chain code** (`IR`, 32B) —
  free reject; on match, derive pubkey (1 mult) and compare (33B) to confirm; optionally
  re-derive & print a child address the user recognizes.
- **address target:** decode once → `(script_type, program)`. Per (path,index): pubkey
  (mults per §2.4), build program per script_type (§2.5), `memcmp`. On hit, re-encode the
  address + print derivation path + index + **the recovered xprv/WIF** so the user can
  import.
- Always **confirm a hit fully** before declaring success (recompute end-to-end, print
  everything), exactly as bip38rxcrack revalidates before printing the WIF.

Output on success (mirror bip38rxcrack's style): the passphrase (or recovered words),
the matching derivation path + index, the address, and the private key (WIF / xprv), plus
the librxe keyspace index of the hit.

---

## 7. The BIP39 checksum & words mode (secondary but powerful)

A BIP39 mnemonic encodes `ENT` bits of entropy + `ENT/32` checksum bits (the last word's
low bits are `SHA256(entropy)[:ENT/32]`). So **only 1 in 2^(ENT/32) random word combinations
is a valid mnemonic**: 12 words → 4 bits → **1/16**; 24 words → 8 bits → **1/256**.

- **This is a pre-filter that costs one SHA-256 and rejects most candidates *before* any
  PBKDF2 or EC.** Enormous in words mode.
- **⚠️ It does NOT help passphrase mode.** There the mnemonic is fixed and already valid;
  the checksum tells you nothing about the passphrase. State this clearly so nobody "adds
  the checksum optimization" to the passphrase path — it's a no-op there.

**Words-mode use cases, all natural for `librxe`:**
- **Known words, unknown order** — a **permutation** search. `librxe`'s `{{ … }}` permutation
  operator over the known words enumerates this directly; the checksum rejects 15/16 (or
  255/256) before the KDF. (12! is huge, but with the checksum filter and the fact that most
  reorderings die instantly, plus known partial order, it's often feasible.)
- **One (or few) missing words** — a **dictionary** position over the BIP39 wordlist:
  `word1 … [:bip39-en:] … word12`. One missing word = ≤2048 candidates × 1/16 valid ≈ 128
  KDFs. Trivial. Two missing ≈ feasible. Beyond that, needs more known constraints.
- **A typo in one word** — alternation over the plausible corrections at that position
  (or the whole wordlist at that position, like a missing word).

Words mode requires the **official BIP39 wordlists** (2048 words, 10 languages) bundled or
resolvable as special dictionaries (§8), and it validates candidate mnemonics (checksum)
and detects language.

### 7.1 Joint mode — both unknown (the product search)
When the user remembers only the *shape* of both the mnemonic and the passphrase, search the
**product** of the two keyspaces. Don't try to express this as one flat regex — the two pieces
play different roles in the KDF (mnemonic is the HMAC **key**, passphrase is in the **salt**),
and the mnemonic must be space-joined from a wordlist and checksum-valid. Implement it as a
**nested product of two `librxe` enumerations**:

```
for each mnemonic-candidate M in words-keyspace (librxe):        # OUTER, DIM 1a
    if not checksum_ok(M):  continue                            # ~15/16 or ~255/256 die here, pre-KDF
    ipad,opad = HMAC_SHA512_key_schedule(NFKD(M))               # computed ONCE per valid M
    master_key_setup = ...                                      # (mnemonic is the HMAC key)
    for each passphrase-candidate p in passphrase-keyspace:      # INNER, DIM 1b
        seed = PBKDF2_with(ipad,opad, salt="mnemonic"||NFKD(p)) # reuse the shared key schedule
        ... derive + match (DIM 2 as usual) ...
```

Why this structure matters:
- **Checksum first (outer):** only valid mnemonics ever reach the passphrase sweep, cutting the
  effective outer set by 16× (12-word) or 256× (24-word) *before* any expensive work.
- **Key-schedule sharing (outer→inner):** the HMAC ipad/opad depend only on the mnemonic, so
  compute them once per valid mnemonic and reuse across the whole inner passphrase sweep — a
  real, free saving because the inner loop is where the volume is.
- **Sharding still works:** the product cardinality is `|words| × |passphrase|`; `librxe`'s
  unrank gives an O(1) bijection into each factor, so a global shard index maps to
  `(m_idx, p_idx)` and the existing sharding/double-buffer machinery applies unchanged.
  (Report *tried* separately from *index range*, since the checksum filter skips indices —
  bip38rxcrack already distinguishes these.)
- **Honesty:** the keyspace is a **product**, so it explodes fast. This mode is only feasible
  when *both* shapes are genuinely tight; the `--estimate` gate (§14) matters most here. Make
  the multiplication explicit to the user before launching.

---

## 8. Dictionaries & languages

Two distinct dictionary needs — don't conflate them:

1. **Passphrase dictionaries (arbitrary).** For passphrase-mode regexes that reference
   `[:name:]`. **Reuse bip38rxcrack's `-D` mechanism verbatim** (it already ports rxenum's
   resolver: `rxe_set_dict_resolver`, `[:name:]` → `dir/name.dict`, `atexit(rxe_free_dicts)`).
   Users bring their own wordlists (common passwords, pet names, etc.).
2. **BIP39 official wordlists (fixed, checksummed).** Needed only for **words mode** and for
   parsing/validating/detecting the language of the known mnemonic. Ship the 10 official
   lists (english, japanese, korean, spanish, chinese-simplified, chinese-traditional,
   french, italian, czech, portuguese) as data, exposed as `[:bip39-en:]`, `[:bip39-ja:]`, …
   Most users are **english**; `--lang` overrides, default = **autodetect** from the known
   mnemonic (each language's list is disjoint enough to detect).
   - Japanese passphrase/mnemonic joins words with an ideographic space and requires the
     NFKD handling from §2.1 — another reason normalization is not optional.

---

## 9. Performance model & estimates (put real numbers in the README)

Per **passphrase candidate**: ~4096 SHA-512 compressions (the KDF, ~99% of cost) + DIM-2
(a few HMACs + 0–3 fixed-base mults, or **zero EC** with an xpub) + a couple of hashes.

| Backend | bip38rxcrack (measured) | bip39rxcrack (estimated) | Speedup |
|---|---|---|---|
| **CPU / core** | ~4–5 cand/s | **~1–5 K cand/s** | ~250–1000× |
| **GPU (5090-class)** | ~1 KH/s | **~10⁵–10⁶ cand/s** | ~100–1000× |

Why: BIP38's scrypt is **memory-hard** (latency-bound → ~4–5/s/core); BIP39's PBKDF2-SHA512
is **plain streaming compute**. Notes that matter:
- **No SHA-512-NI on x86** (SHA-NI covers only SHA-1/256). Fast CPU needs **SIMD SHA-512**
  (4–8-way AVX2). Scalar ≈ 1–1.5 K/s/core; SIMD ≈ 3–8 K/s/core.
- **GPU KDF is embarrassingly parallel and non-memory-hard** → the *KDF alone* can exceed
  10⁶ cand/s on a 5090. The **bottleneck then moves** to DIM-2:
  - **xpub target → no EC → GPU stays KDF-bound → ~10⁶/s realistic.**
  - **address target → host secp256k1 caps at ~10⁴–10⁵/s across cores** and becomes the
    limiter; to cash in the KDF you'd put **secp256k1 on the GPU** (proven feasible — vanity
    generators do tens of M pubkeys/s). Tier this (§10/§12).
- **Fan-out multiplies DIM-2.** Keep defaults tight; report the effective multiplier.

Headline for docs: *~1000× faster than BIP38 — because the memory-hard scrypt is replaced by
a plain 2048-round hash, and the elliptic-curve work is a few fast fixed-base mults that
never bottleneck on CPU (and vanish entirely when you have an xpub).*

---

## 10. Architecture & code reuse (fork bip38rxcrack)

Start by **copying bip38rxcrack's skeleton** and swapping two organs:

Reuse as-is: arg parsing & usage/banner style, `-D` dictionaries, `-p` progress/ETA,
sharding via `rxe_foreach`, the **host↔GPU split** (GPU does the KDF; host does verify,
double-buffered so host verify overlaps the next GPU batch), env-var conventions, base58check,
RIPEMD-160/HASH160, the gmp secp256k1, the oracle+selftest harness, the Makefile shape.

**Swap #1 — the KDF kernel:** `scrypt-ROMix` → **`PBKDF2-HMAC-SHA512` (2048)**. This is
*simpler*: no V scratchpad, no time-memory `gap`, and — because it's fast and bounded — **no
watchdog chunking / phased-vs-mono machinery** at all (that whole complexity in bip38rxcrack
existed to survive display-GPU watchdogs on a slow memory-hard kernel; unnecessary here).
The kernel produces the 64-byte seed (or, if we push derivation onto the GPU, keeps hashing
the BIP32 HMAC chain). SHA-512 kernel must be gated byte-exact vs CPU.

**Swap #2 — the host finish:** BIP38 AES-decrypt/verify → **BIP32 derive + target match**
(§2.4–§2.5, §6). New code: BIP32 CKDpriv, script-type program builders, **bech32/bech32m**,
taproot tweak, the path-plan iterator, xpub decode + chain-code compare.

**GPU tiers:**
- **Tier A (v1):** GPU KDF only; **host-side** derivation + secp256k1 (reuse bip38rxcrack's).
  Great for CPU and for xpub-target GPU (no EC). For address-target GPU it will be
  host-EC-bound but still fast and simple. Ship this first.
- **Tier B:** push the **BIP32 HMAC chain onto the GPU** too (all SHA-512). For **xpub
  targets this makes the whole crack GPU-resident with a 32-byte chain-code compare on
  device and no secp256k1 anywhere** — the big win.
- **Tier C (optional, later):** **secp256k1 on the GPU** for **address** targets, to stop
  host EC being the ceiling. Biggest effort; only if address-target GPU throughput matters.

---

## 11. CLI sketch (make it concrete, keep it bip38rxcrack-shaped)

```
bip39rxcrack [options] <regex>

  Required target (at least one; there is no embedded checksum to verify against):
    --xpub <xpub>            account (or root) extended pubkey  [best: enables no-EC crack]
    --address <addr>         known address (repeatable); type inferred from format

  Known secret / mode (the mode is INFERRED from what is fixed vs. a pattern):
    --mnemonic "<words>"     the known 12/24-word mnemonic (FIXED)  -> passphrase mode
    --mnemonic "<rxe over [:bip39-*:] / {{ }} / alternations>"  (PATTERN) -> words or joint mode
    --mnemonic-file <f>
    --lang <english|...>     BIP39 wordlist language (default: autodetect)
      # fixed --mnemonic + passphrase <regex>   -> PASSPHRASE mode (primary)
      # --mnemonic PATTERN + no/empty passphrase -> WORDS mode  (checksum pre-filter on)
      # --mnemonic PATTERN + passphrase <regex>  -> JOINT mode  (product; §7.1)

  Derivation plan (DIM 2):
    --path "m/84'/0'/0'/0/0" exact single path
    --paths bip44,bip49,bip84,bip86     (default: infer from target; else all four)
    --preset electrum-segwit|electrum-legacy|...
    --accounts 0-2   --change 0,1   --gap N   --uncompressed

  Keyspace / dictionaries (DIM 1):
    -D <dir>                 dictionary search dir for [:name:]  (as bip38rxcrack)
    --estimate               print keyspace size, path-plan size, and ETA; do not crack
    --dry-run N              print N sample candidates (first + random) and exit

  Engine (identical to bip38rxcrack):
    -j <jobs>  -G  --backend opencl|cuda  -b <batch>  -p  -c <count>
```

The positional `<regex>` is always the **passphrase** pattern; the **mnemonic** pattern (when
unknown) goes in `--mnemonic` (often a `{{ }}` permutation of known words, or `[:bip39-en:]`
at unknown positions). Which of the three modes runs is then implied by which side is fixed
vs. a pattern (table above). **Joint mode = both are patterns.** Document all three plainly,
and always print the effective keyspace (and, for joint mode, the explicit product) before
running.

---

## 12. Milestones (ordered, cold-start-executable)

**Build philosophy: estimate first, crack second.** The tool is useful — and *safe* — as a
pure keyspace/effort **calculator** before any crypto exists; each mode's enumeration is then
added incrementally, always behind the same **estimate-then-run** gate. **We start by shipping
BOTH estimators — CLI and web — as the first deliverables** (M0–M2), before a single line of
cracking code. They share **one estimation core** over `librxe` (exact cardinality + unrank),
so they can never disagree, and each **handles no secrets** (only pattern *shapes* + target
*type*). THE LAW (byte-exact vs the oracle) governs the crypto/crack steps (M4 onward); the
calculator has its own correctness (librxe cardinality is exact; the sampler uses unrank).

- **M0 — Shared estimator core + CLI calculator (NO crypto).** Build the estimation as a
  **standalone core** (the piece both front-ends reuse): parse the passphrase regex and/or
  `--mnemonic` pattern via `librxe`; compute exact set cardinalities, the checksum-survival
  fraction (**exact when the words-set is small enough to enumerate, sampled otherwise — and
  say which**), the path-plan multiplier (§5), and the **product cardinality** for joint mode
  (§7.1). Surface it in the CLI: total candidate count with a breakdown; `--dry-run N` prints
  the first N and N random candidates (via unrank) so the user *sees* what their pattern
  generates. No rate/ETA yet. Ships as a standalone *"BIP39 effort calculator."*
- **M1 — Web estimator (jsrxe, client-side).** The same estimation core compiled to the
  browser via **jsrxe / emscripten** (librxe already builds under `emcc`; jsrxe exists). An
  interactive page where the user adds constraints and **watches the keyspace collapse**, with
  no backend and **no secrets leaving the browser** (only pattern shapes + target type). This is
  the "typical user never touches the CLI" path and the teaching tool. Keep the estimation model
  (§9/§14) as the **shared spec** so web and CLI never disagree.
- **M2 — Calibrated ETA (both front-ends).** CLI `--calibrate` microbenchmarks **real
  PBKDF2-HMAC-SHA512(2048)** on this CPU (later GPU); the web build calibrates the **browser's**
  measured rate (jsrxe's JS-CPU workers + WebGPU) and *also* projects the native-CLI rate from
  shared constants. Combine with the count + DIM-2/target model (xpub → no EC; address → EC +
  fan-out) → an **honest wall-clock ETA**. Present **time-to-exhaust** as the planning number
  (guaranteed upper bound), distinct from expected-time-to-hit. Emit a **green/yellow/red
  verdict** and, when poor, concrete **narrowing levers** (provide an xpub, tighten a segment,
  drop `--gap`, remember one more word ÷2048). Optionally require `--yes` above an ETA threshold.
- **M3 — Oracle & vectors.** Python oracle: mnemonic(+passphrase, NFKD) → seed → BIP32
  master → derive `m/{44,49,84,86}'/0'/0'/{0,1}/i` → P2PKH/P2SH-P2WPKH/P2WPKH/P2TR address +
  account xpub. Gate against **official BIP39 vectors** (passphrase "TREZOR") and **BIP32
  vectors**; add BIP44/49/84/86 vectors from a reference wallet. Ground truth for all crack code.
- **M4 — CPU crypto, byte-exact.** PBKDF2-HMAC-SHA512, BIP32 CKDpriv (hardened+normal),
  secp256k1 (reuse), HASH160, base58check (reuse), **bech32/bech32m (new)**, taproot tweak.
  Selftests vs M3 — and confirm M2's calibration KDF was byte-correct. `--test-*` flags.
- **M5 — CPU crack end-to-end (passphrase mode, single path).** Wire the enumeration to the
  pipeline, `-D`, `-p`, `--address`/`--xpub`, single `--path`. Recover a known test wallet's
  passphrase from a regex. Minimum lovable tool — and the estimate now precedes every run.
- **M6 — Path fan-out + inference + xpub fast path.** DIM-2 iterator, format→purpose
  inference, `--paths/--accounts/--change/--gap/--preset`, chain-code (no-EC) xpub path.
- **M7 — Words mode + Joint mode.** BIP39 wordlists (10 langs) + checksum pre-filter +
  language autodetect; permutation (`{{ }}`) / missing-word / typo patterns. Then **joint
  mode** (§7.1): nested product enumeration (outer = checksum-filtered mnemonic, inner =
  passphrase), shared HMAC key-schedule, product-cardinality sharding. (The M0 core already
  models all three modes, so this is enumeration-plumbing, not new estimation.)
- **M8 — GPU Tier A/B.** OpenCL + CUDA PBKDF2-SHA512 kernel, host verify, double-buffer,
  byte-exact gate; feed measured GPU rate back into `--calibrate`. Then **Tier B** (GPU BIP32
  chain + on-device chain-code compare for xpub targets — the headline GPU number).
- **M9 — Polish.** man page, README (with honest numbers & the xpub tip), `make test`,
  `--uncompressed`, extra presets, the pattern cookbook (§14). **Tier C (GPU secp256k1)** only
  if address-target GPU throughput demands it.
- **Future.** Multi-GPU / multi-machine (reuse bip38rxcrack's sharding plan); Electrum-native
  seed scheme (§16); a browser build that also *runs* small cracks via jsrxe's WebGPU (the
  estimator is the standalone win; cracking in-browser is a bonus later).

---

## 13. Correctness discipline

- **Oracle first, always.** No C path ships without a byte-exact selftest vs the Python
  oracle, and no GPU kernel without a byte-exact check vs the CPU reference. Gate against the
  **reference**, never a sibling model.
- **Published vectors** anchor the oracle: BIP39 (Trezor) seed/xprv vectors, BIP32 derivation
  vectors, and known (mnemonic, passphrase, path)→address triples from a reference wallet for
  each of 44/49/84/86 incl. taproot.
- **Confirm every hit fully** (re-derive end-to-end) before printing success.

---

## 14. The UI / regex-authoring problem (this is what makes or breaks the tool)

The tool is only practical because the user *knows something*. A cold full-charset search is
out of reach — say so plainly. The design must **steer the user to encode what they remember**
and **stop them from launching hopeless searches.** Concretely:

- **Estimate first, crack second — the calculator is the front door, not an afterthought.**
  The tool ships (M0/M1) as an effort calculator *before* it can crack anything, and every
  crack run is preceded by the estimate. Print keyspace size, the checksum-survival fraction
  (exact or sampled — labeled), the path-plan multiplier, the **calibrated** rate (from
  `--calibrate` on this machine, not a hardcoded guess), and the **time-to-exhaust** as the
  honest planning number (guaranteed upper bound; note expected-time-to-hit ≈ half if the
  guess is in the set). Emit a **green/yellow/red verdict**: green (minutes/hours → go),
  yellow (days/weeks → consider narrowing), red (years+ → narrow or find more constraints).
- **Coach on red, don't just refuse.** Name the levers that actually move the number:
  *provide an account xpub* (removes secp256k1 from the hot loop entirely, §3), *tighten a
  segment*, *lower `--gap`*, *remember one more word* (each known word divides the words-space
  by 2048), *reduce the path fan-out*. Consider requiring `--yes` above an ETA threshold.
- **`--dry-run N`** prints the first N and N random candidates so the user *sees* what their
  regex actually generates — the #1 way to catch a mistaken pattern before a long run.
- **A pattern cookbook** in `--help` and the man page: known prefix + variable suffix
  (`Correct(horse|Horse)?\d{0,2}`), case ambiguity (`[Tt]esting`), "a word or two I might've
  used" via `-D`/`[:name:]`, optional segments `(…)?`, digit tails `\d{1,2}`, leet subs,
  separators. Teach by example, echoing bip38rxcrack's examples.
- **Frame the tool honestly:** "for a *remembered* passphrase's shape, not blind
  brute-force." Motto on the banner.
- **Nudge toward the xpub** whenever a target is an address: mention that an account xpub
  makes the crack dramatically leaner (§3).

---

## 15. What Kiko's list was missing (added above — summary)

The original brainstorm covered: no-scrypt/PBKDF2, secp256k1 in BIP32, path fan-out with
known/unknown/inferrable paths, Electrum's short paths, the xpub fast-path, the checksum
pre-filter, multi-language dictionaries, and the regex-authoring UI. Added here:

1. **No embedded check ⇒ a target (address/xpub) is mandatory** — the defining structural
   difference from BIP38; it drives the CLI and verify path. (§0.2, §3)
2. **NFKD normalization is mandatory** (BIP38 punted; BIP39 cannot). (§2.1)
3. **The account-xpub path can be entirely secp256k1-free** (compare the 32-byte chain code)
   → the ideal GPU workload and the single biggest throughput lever. (§3, §6, §10-TierB)
4. **Checksum helps words mode only — NOT passphrase mode** (mnemonic is fixed there). (§7)
5. **Permutation/reorder of known words via `librxe {{ }}`** + checksum = a killer words-mode
   use case; plus missing-word and single-word-typo patterns. (§7)
6. **Taproot (BIP86) needs an extra tweak mult + bech32m**, and we need bech32/bech32m
   (bip38rxcrack has only base58); **decode the target once** to skip per-candidate encoding.
   (§2.5)
7. **The bottleneck moves on GPU** (KDF is cheap): xpub → stays KDF-bound (~10⁶/s);
   address → host-EC-bound unless secp256k1 goes on-GPU (tiered). (§9, §10)
8. **Seed computed once; path fan-out reuses it** — the structuring that keeps DIM-2 cheap on
   CPU and tells you where the GPU ceiling is. (§4)
9. **`--estimate` + `--dry-run` as core UI safety**, and honest ETA-gating. (§14)
10. **Electrum's own seeds are a *different KDF*, not BIP39** — a pluggable seed-scheme,
    out of scope for v1 but noted so nobody assumes an Electrum seed "just works." (§8, §16)
11. Legacy **uncompressed** keys; account/change/gap scanning knobs; language autodetect &
    Japanese spacing. (§2.5, §5, §8)

---

## 16. Open questions / decisions to make when we start

- **NFKD implementation:** bundle a compact normalizer vs. depend on ICU/utf8proc vs.
  ASCII-only v1 with a warning. (Recommend a small bundled NFKD; it's not optional.)
- **Electrum-native seed scheme:** support as a pluggable KDF (salt `"electrum"`, its own
  version/checksum, its own normalization) or leave out of v1? (Recommend: architect the
  "seed scheme" as pluggable, ship BIP39 only in v1.)
- **Default path-plan** when only an address is given: infer purpose from format and try
  `account 0, change 0, gap 1` — confirm this is the right tight default.
- **GPU secp256k1 (Tier C):** build only if address-target GPU throughput proves to matter;
  xpub-target (Tier B) may make it moot for the common case.
- **ETA gate threshold** for requiring `--yes`.
- **Reuse vs. vendor** of bip38rxcrack code: shared static lib in `../rxe`-style, or copy?
  (Copy the few files initially; consider factoring a shared `libbtccrypto` later.)

---

*End of plan. Build under the same supervise/byte-exact model as bip38rxcrack; keep the
family's conventions and its motto: **cracking hard is alright, but smart is better.***
