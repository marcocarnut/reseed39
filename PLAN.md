# (re)seed39 / bip39rxcrack — Design & Roadmap

> *Cracking hard is alright, but smart is better.*

**What this is:** the design record for **(re)seed39** (the browser app) and **bip39rxcrack**
(the native CLI it will hand big jobs to). It recovers a **BIP39 or Electrum wallet seed you
half-remember** by enumerating a **regular-expression / dictionary keyspace** (via `librxe`) and
running each candidate through the full seed→BIP32→address pipeline until it matches a target.

**Read this if you're picking the project up cold.** §0 is the current lay of the land; §2 is the
cryptographic ground truth (unchanged — the code is gated byte-exact against it); §9–§12 are the
**forward plan**, whose center of gravity has moved: the browser cracker is **shipped**, and the
native CLI's entire reason to exist is now **extracting topmost performance from high-end GPUs and
GPU/CPU clusters.**

**Sibling / template:** `bip38rxcrack` (`github.com/marcocarnut/bip38rxcrack`) — CPU + OpenCL +
CUDA, **multi-GPU shipped** (fork/exec one CUDA-pinned child per GPU, ~2× on 2× RTX 5090; plus
`multigpu.sh`/`--range`/`--count` to shard across machines). Its scaffolding — sharding via
`rxe_foreach`, host↔GPU double-buffer, `-D` dictionaries, `-p` ETA, the oracle+byte-exact gate —
is exactly what the (re)seed39 CLI forks.

---

## 0. Where we are (2026-08) — the pivot, made real

The original plan was "estimate first, crack second; the CLI is the product." **That flipped.**
The browser turned out to be a *great* place to actually crack the small-to-medium jobs most users
have, and a perfect teaching / planning surface. So:

**SHIPPED — (re)seed39, a full client-side cracker** (repo `bip39rxcrack`, dir `estimator/`,
served `python3 -m http.server 8877` → `/estimator/index.html`; git-local, no public remote yet):

- **Estimate + crack unified in one page.** Auto mode selection by cardinality (passphrase /
  words / joint). Live cardinality + dry-run from `librxe`-wasm.
- **BIP39 and Electrum v2** seed schemes; **address (44/49/84/86 incl. taproot) and xpub** targets;
  the xpub path is **EC-free** (chain-code compare).
- **Both engines in-browser:** multicore **CPU** (Web Workers, each with its own librxe core so the
  enumeration sweep parallelizes) and **WebGPU** (WGSL PBKDF2-HMAC-SHA512 seed kernels — a
  fixed-key kernel for passphrase mode and a **per-lane-key** kernel for words mode).
- **Checksum pre-filter** (toggle), a **fast one-block SHA-256 sieve** so the host keeps the GPU
  fed, W=8 fixed-base **comb** for host secp256k1, **batch-unrank** (one seek + N odometer steps),
  parallel-EC derive pool, double-buffering — the low-hanging browser perf fruit is picked.
- **Real in-browser benchmark → calibrated ETA** (measures the actual multicore pipeline, not a
  single-core fiction ×cores) + a **9-tier verdict**.
- **Robustness for long runs:** WebGPU **device-loss self-heal** + adaptive thermal **cooldown**;
  **checkpoint/resume** across reloads (on-device only — seed fragments never touch the URL).
- **Share/bookmark** links (`#hash` state, with a privacy warning), OS share sheet on mobile,
  per-box tooltips; **en/pt** i18n; an online-safety banner.
- **THE LAW honored:** every primitive byte-exact vs a published vector; every GPU kernel byte-exact
  vs the CPU reference. Gates: `test/test_crypto.js`, `test/test_electrum.js`, `test/test_p{1,2}.js`.

**The one structural fact that still drives everything:** BIP39/Electrum embed **no self-check**
(§0.2 below), so the user **must supply a target** (address or, ideally, xpub). That is why the
tool is a *targeted* cracker, not a blind one.

### 0.1 What the CLI is *for* now — the mission

The browser handles what a browser can. The **native CLI exists to go where the browser can't:
maximum throughput on serious hardware.** Concretely, the CLI's job is to **extract topmost
performance from high-end GPUs and from GPU/CPU clusters** —

- a **big keyspace** (a wide joint search, many unknown words, a long passphrase pattern) that would
  take a browser weeks but a rack of GPUs an afternoon;
- **multi-GPU** on one box, and **multi-machine** fan-out across a cluster;
- **native SIMD/CUDA** PBKDF2-SHA512 and (for address targets) **on-GPU secp256k1**, none of which
  a browser can reach.

The browser is the **front door and the router**: it estimates, calibrates, and — when the verdict
says the job is too big for here — tells the user to run the **same pattern** on the CLI/cluster.
The estimation core is shared (`librxe` cardinality + unrank), so the browser's size/feasibility
numbers and the CLI's are the same numbers. This is the through-line of the whole roadmap below.

### 0.2 The KDF, briefly (why this is fast, and why the CLI wants GPUs)

Seed derivation is `PBKDF2-HMAC-SHA512` with **2048 iterations** (`dkLen=64` ⇒ ~4096 SHA-512
compressions/candidate) — **not** scrypt. It is **plain streaming compute**, embarrassingly
parallel, **not memory-hard**. So:

- It is intrinsically **~100–1000× faster** than bip38rxcrack's memory-hard scrypt.
- It is the **ideal GPU workload** — which is precisely why the CLI's payoff is on GPUs/clusters,
  and why an **xpub** target (no EC in the loop) can keep a big GPU KDF-bound at ~10⁶ cand/s.

---

## 1. Context: `librxe`, the rxe family, conventions

**`librxe`** (sibling `rxe` repo at `../rxe`, `RXE_DIR` overrides) is a regex-**enumeration**
library: it treats a finite regex as a **set** and gives a **bijection between `[0,N)` and the
strings of that set** — O(1) `unrank(i)` and `rank(s)`. Kiko's thesis holds: *the integer bijection
and cheap unrank are the killer feature* — they make **sharding trivial** (`rxe_foreach(from,
count)`), which is exactly what powers multicore, GPU batching, double-buffering, and multi-machine
work-splitting. Everything about scaling — browser workers today, cluster shards tomorrow — leans
on that.

**Family & motto** — keep naming/behavior consistent:

- **`rxe` / `rxenum` / `rxejit`** — the core library + CLIs; `rxejit` JIT-compiles a finite regex
  to C/GPU kernels. `rxenum` provides the **`[:name:]` dictionary** mechanism (`-D dir` search).
- **`bip38rxcrack`** — our CLI template: CPU/OpenCL/CUDA, **multi-GPU + cross-machine sharding**,
  byte-exact gated. **Read its source; we fork its structure and its scaling plan.**
- **`jsrxe`** — the browser/WebGPU incarnation of the family; (re)seed39 is a cousin of it and
  reuses its WGSL/worker patterns.

**The motto** — `Cracking hard is alright, but smart is better.` It's in the banner, README, and
(future) man page. The point of these tools is that the user *knows something* that collapses an
impossible keyspace into a feasible one.

**Consistency rules:** binary `bip39rxcrack`; man page `bip39rxcrack.1`; env vars **`RXE39_`**
(mirror `RXE38_GPU_GAP`, `RXE38_BACKEND`, `RXE38_VERIFY_THREADS`, …). Link `librxe` from `../rxe`
(`RXE_DIR` overrides). Makefile: `make` / `make gpu` (OpenCL) / `make cuda` / `make test`.
**THE LAW (inherited):** every GPU kernel gated byte-exact vs the **CPU reference**; every crypto
primitive vs a **published vector**; never gate a backend against a sibling model. Collaboration:
a box-agent builds/measures on real NVIDIA hardware (RTX 5090D on GPUhub) via Remote Control; the
integrator is correctness authority + sole git owner (re-establish when CLI work starts).

---

## 2. The cryptographic pipeline (ground truth the code matches)

This is the spec. The browser crypto (`estimator/bip39crypto.js`, `electrum.js`) already matches it
byte-exact; the future C/GPU code is gated the same way.

### 2.1 Normalization — mandatory
**BIP39 requires Unicode `NFKD`** of *both* mnemonic and passphrase before PBKDF2 (ASCII is a
no-op; non-Latin differs). **Electrum normalizes differently** (§8/§16): NFKD + lowercase + strip
combining marks + collapse whitespace. Both are implemented.

### 2.2 Mnemonic → 512-bit seed
```
seed = PBKDF2( PRF=HMAC-SHA512, P=NFKD(mnemonic),
               S="mnemonic" || NFKD(passphrase),   c=2048, dkLen=64 )
```
(Electrum: salt `"electrum" || normalize(passphrase)` — the only KDF difference.) `dkLen=64` ⇒ one
HMAC block ⇒ ~4096 compressions. In **passphrase/joint** mode the HMAC key (mnemonic) is fixed per
mnemonic ⇒ **precompute ipad/opad once**, reuse across the passphrase sweep (this is the fast GPU
midstate path). The salt varies per candidate, so the 2048-chain is redone each time.

### 2.3 Seed → BIP32 master
`I = HMAC-SHA512("Bitcoin seed", seed)`; `IL` = master priv (must be nonzero and `< n`),
`IR` = master chain code.

### 2.4 BIP32 CKDpriv
```
hardened (i ≥ 2^31):  I = HMAC-SHA512(c_par, 0x00 || ser256(k_par) || ser32(i))   // NO ec mult
normal   (i <  2^31): I = HMAC-SHA512(c_par, serP(point(k_par)) || ser32(i))       // needs parent PUBKEY
k_i = (parse256(IL) + k_par) mod n ;  c_i = IR
```
Only **normal** steps need a fixed-base `k·G` mult; hardened steps are pure hashing. A full
`m/purpose'/coin'/account'/change/index` address costs **3 fixed-base mults** (fewer with xpub, §6).

### 2.5 Pubkey → address / output program
Decode the target **once** into `(script_type, program_bytes)`; per candidate compute the program
and `memcmp` — **no per-candidate base58/bech32 encoding**.

| BIP | Path | Script | Program | Address |
|-----|------|--------|---------|---------|
| 44  | `m/44'/0'/a'/c/i` | P2PKH | `HASH160(cpub)` | base58 `1…` |
| 49  | `m/49'/0'/a'/c/i` | P2SH-P2WPKH | `HASH160(0x0014‖HASH160(cpub))` | base58 `3…` |
| 84  | `m/84'/0'/a'/c/i` | P2WPKH | `HASH160(cpub)`, witver 0 | bech32 `bc1q…` |
| 86  | `m/86'/0'/a'/c/i` | P2TR | x-only tweaked `Q_x` (BIP86 TapTweak) | bech32m `bc1p…` |

Format → likely purpose (`1…`→44, `3…`→49, `bc1q…`→84, `bc1p…`→86) prunes the path fan-out. All four
(incl. taproot tweak, bech32/bech32m, uncompressed legacy) are implemented and gated in the browser.

---

## 3. The target requirement & the xpub fast path

No embedded check ⇒ a **target is mandatory**. Ranked best→worst:

1. **Account xpub** (`m/44'/0'/0'` etc.) — the jackpot: carries the node's **chain code**. Derive
   the **hardened path only** (pure HMAC-SHA512, **zero mults**) and compare the resulting chain
   code directly — **no secp256k1 anywhere in the hot loop.** The ideal GPU/cluster workload; flag
   it loudly: *"have an xpub? this runs an order of magnitude leaner."*
2. **Root xpub `m`** — compare master chain code; cheapest possible.
3. **A known address** — must derive to the pubkey + build the program (3 mults/(path,index)),
   guessing `change∈{0,1}` and `index∈[0,gap)`. Real EC in the loop → the case that most wants
   **on-GPU secp256k1** at cluster scale (§10 Tier C).
4. **Several addresses** — match any; better odds of a low index.

**Rule:** if the user can export their **account xpub**, tell them to — it removes secp256k1 from
the hot path and multiplies throughput. Both browser and CLI infer the target type from format.

---

## 4. Two search dimensions

```
for each DIM-1 candidate (passphrase and/or mnemonic) in the librxe keyspace:   # expensive: the KDF
    seed = seed(mnemonic, passphrase)          # ~4096 SHA-512
    for each (script_type, account, change, index) in the path-plan:            # cheap: reuse seed
        node = derive(...);  if matches(node, target): HIT
```
DIM-1 (the KDF) dominates on CPU; on GPU it's so cheap that **DIM-2 (EC + fan-out) becomes the
bottleneck** for address targets — the reason the xpub path (no EC) keeps a GPU KDF-bound and the
address path wants on-GPU secp256k1 at scale. Words mode inverts DIM-1 to the mnemonic enumeration
(with the checksum pre-filter, §7). Joint mode is the **nested product** (§7.1).

---

## 5. Derivation-path handling (DIM-2)

Same knobs the browser exposes and the CLI will mirror: `--path` (exact), `--paths
bip44,bip49,bip84,bip86` (default: infer from target; else all four), `--accounts`, `--change`,
`--gap N` (default tight — a real match is usually index 0), `--preset electrum-standard|
electrum-segwit|…`, `--uncompressed` for legacy P2PKH. Each extra (path × account × change × index)
is another DIM-2 iteration — cheap on CPU, potentially dominant on GPU. **Infer narrowly by default,
let the user widen; print the effective path-plan size.**

---

## 6. Verification

- **xpub:** derive hardened path (no mult) → compare **chain code** (free reject); on match, derive
  pubkey (1 mult) to confirm.
- **address:** decode once → per (path,index) build the program → `memcmp`; on hit, re-encode +
  print path/index + WIF/xprv.
- **Always confirm a hit fully** (re-derive end-to-end) before declaring success. Output mirrors
  bip38rxcrack: the recovered secret, the matching path+index, the address, the private key, and the
  librxe keyspace index of the hit.

---

## 7. Checksum & words mode

A BIP39 mnemonic's last word carries `ENT/32` checksum bits ⇒ only **1/16** (12-word) or **1/256**
(24-word) random word-combos are valid. The checksum is **one SHA-256** that rejects most candidates
**before** any PBKDF2/EC — huge in words mode, a **no-op in passphrase mode** (the mnemonic is
fixed). In the browser it's a toggle (off = also find off-dictionary/custom words). Words-mode uses:
**unknown order** (`{{ }}` permutation), **missing word** (`[:bip39-en:]` at a position), **typo**
(alternation). The **last-word shortcut** — when the *unknown token is the final word*, construct
the ~8 (24w)/~128 (12w) valid last-words directly instead of sieving — is understood and proven, and
is a high-value optimization for both front-ends (needs pattern-shape detection).

### 7.1 Joint mode — the product
Both unknown ⇒ search `|words| × |passphrase|` as a **nested product of two enumerations** (the two
play different KDF roles — mnemonic = HMAC key, passphrase = salt — so it is *not* one flat regex):
```
for each mnemonic M (outer):  if not checksum_ok(M): continue         # prune 16×/256× pre-KDF
    ipad,opad = HMAC_key_schedule(NFKD(M))                            # shared across the inner sweep
    for each passphrase p (inner):  seed = PBKDF2(ipad,opad, salt=…p); derive; match
```
Checksum-first (outer), key-schedule-shared (outer→inner), and sharding still works (a global shard
index maps to `(m_idx, p_idx)`). It explodes fast, so the estimate matters most here — **exactly the
"too big for a browser → run it on the cluster" case.**

---

## 8. Dictionaries & languages

Two needs: **arbitrary passphrase dictionaries** (`[:name:]` via the `-D` resolver, reused from
bip38rxcrack) and the **official BIP39 wordlists** (fixed, checksummed) for words mode. English is
preloaded; the other nine official lists slot in identically (`registerDict`). The Electrum English
list is **byte-identical** to BIP39's (same sha256), aliased `[:electrum-en:]`. Japanese needs the
ideographic-space join + NFKD (another reason normalization isn't optional).

---

## 9. Performance model & the case for the CLI

Per candidate: ~4096 SHA-512 (the KDF, ~99% of cost) + DIM-2 (a few HMACs + 0–3 fixed-base mults,
or **zero EC** with an xpub).

| Backend | scrypt sibling (bip38) | this tool | Why |
|---|---|---|---|
| **Browser CPU** (multicore JS) | — | ~10²–10³ cand/s | JS PBKDF2, sweep-bound |
| **Browser GPU** (WebGPU) | — | ~10⁴ cand/s | iGPU seed kernel |
| **CLI CPU / core** (SIMD SHA-512) | ~4–5/s | ~10³–10⁴/s | plain streaming hash |
| **CLI GPU (5090-class)** | ~1 KH/s | **~10⁵–10⁶ cand/s** | non-memory-hard KDF, ideal for GPU |
| **CLI multi-GPU / cluster** | ~2×/GPU (shown) | **N × the above** | trivial `rxe_foreach` sharding |

Key facts that shape the CLI:
- **No SHA-512-NI on x86** (SHA-NI is SHA-1/256 only) → fast CPU needs **4–8-way AVX2 SHA-512**.
- **The GPU KDF alone can exceed 10⁶ cand/s** on a 5090; the **bottleneck then moves to DIM-2**:
  **xpub → no EC → stays KDF-bound (~10⁶/s)**; **address → host secp256k1 caps at ~10⁴–10⁵/s** unless
  **secp256k1 goes on the GPU** (proven feasible — vanity generators do tens of M pubkeys/s).
- **Sharding is free** (unrank bijection) → multi-GPU on a box and multi-machine across a cluster are
  the same mechanism at different scales.

Headline: *the memory-hard scrypt wall is gone; the work is a plain 2048-round hash that GPUs devour
— so throwing more/bigger GPUs at it scales almost linearly, which is the entire point of the CLI.*

---

## 10. CLI architecture — fork bip38rxcrack, aim at big iron

Start by **copying bip38rxcrack's skeleton** and swapping two organs:

Reuse as-is: arg parsing/usage/banner, `-D` dictionaries, `-p` progress/ETA, **sharding via
`rxe_foreach`**, the **host↔GPU double-buffer** (GPU KDF while host verifies the previous batch),
env-var conventions, base58check, RIPEMD-160/HASH160, the gmp secp256k1, the oracle+selftest
harness, and — crucially — its **multi-GPU + cross-machine machinery** (§10.1).

**Swap #1 — the KDF kernel:** scrypt-ROMix → **PBKDF2-HMAC-SHA512(2048)**. *Simpler*: no V
scratchpad, no time-memory gap, and (being fast and bounded) **no watchdog/phased-vs-mono
machinery** — that whole complexity in bip38rxcrack existed to survive display-GPU watchdogs on a
slow memory-hard kernel; unnecessary here.

**Swap #2 — the host finish:** BIP38 AES-verify → **BIP32 derive + target match** (§2.4–2.5, §6):
CKDpriv, script-type program builders, bech32/bech32m, taproot tweak, path-plan iterator, xpub
decode + chain-code compare. (The browser already has correct, gated JS for all of this to port.)

**GPU tiers — ordered by how much of the win they unlock:**
- **Tier A (first):** GPU KDF only; host-side derive + secp256k1. Great for CPU and for **xpub
  targets** (no EC). Ship this first; it's the minimum that beats the browser by orders of magnitude.
- **Tier B:** push the **BIP32 hardened HMAC chain onto the GPU** too → for **xpub targets the whole
  crack is GPU-resident** (SHA-512-only, 32-byte chain-code compare on device, **no secp256k1
  anywhere**). This is the headline GPU number.
- **Tier C:** **secp256k1 on the GPU** for **address targets**, so host EC stops being the ceiling.
  Biggest effort; do it when address-target cluster throughput demands it.

### 10.1 Multi-GPU and clusters (the CLI's whole point) — reuse bip38rxcrack's proven plan
bip38rxcrack already shipped the model to copy:
- **Multi-GPU on one box:** `--gpus N` = **fork/exec one child per GPU**, each pinned
  (`CUDA_VISIBLE_DEVICES` / OpenCL device index), each cracking a shard; lowest-index-hit wins.
  Measured ~2× on 2× RTX 5090. (No in-process device-threading — the fork/exec pattern won.)
- **Cross-machine:** `--range START:COUNT` / `--count` + a `multigpu.sh`-style launcher shard the
  global `[0,N)` across machines; each node reports its local hit, the coordinator takes the
  lowest global index. Exit codes 0/1/2/3 for found/not-found/error/aborted.
- **(re)seed39 adds nothing new here conceptually** — the seed→match differs, the **sharding,
  double-buffer, and lowest-index merge are identical.** Tier 2 (heterogeneous work-stealing) and
  Tier 3 (a coordinator/swarm across many boxes) are the same roadmap as
  `bip38rxcrack-multigpu-plan`, applied to the faster KDF.

---

## 11. CLI sketch (bip38rxcrack-shaped)

```
bip39rxcrack [options] <passphrase-regex>

  Target (required — no embedded checksum to verify against):
    --xpub <xpub>            account/root extended pubkey   [best: EC-free crack]
    --address <addr>         known address (repeatable); type inferred from format

  Secret / mode (INFERRED from which side is fixed vs a pattern):
    --mnemonic "<words>"       fixed 12/24-word mnemonic         -> passphrase mode
    --mnemonic "<rxe pattern>" [:bip39-*:] / {{ }} / alternation -> words or joint mode
    --lang <english|...>       BIP39 wordlist language (default: autodetect)
    --scheme bip39|electrum    seed scheme (default bip39; electrum = salt "electrum", its checksum)
      # fixed mnemonic + passphrase regex        -> PASSPHRASE   (checksum is a no-op)
      # mnemonic pattern + empty passphrase       -> WORDS        (checksum pre-filter on)
      # mnemonic pattern + passphrase regex       -> JOINT        (product; §7.1)

  Derivation (DIM-2):
    --path / --paths bip44,bip49,bip84,bip86 / --preset electrum-* / --accounts / --change / --gap / --uncompressed

  Keyspace / dictionaries (DIM-1):
    -D <dir>                 [:name:] dictionary search dir
    --estimate               print keyspace + path-plan + calibrated ETA; do not crack
    --dry-run N              print N sample candidates and exit

  Engine (mirror bip38rxcrack) — this is where the CLI earns its keep:
    -j <jobs>                CPU worker threads (AVX2 SHA-512)
    -G / --backend opencl|cuda   GPU backend
    --gpus N                 fork one pinned child per GPU (multi-GPU)
    --range START:COUNT / --count   shard the keyspace (cross-machine clusters)
    -b <batch>  -p  -c <count>
```

The positional `<regex>` is the **passphrase** pattern; the **mnemonic** pattern (when unknown) goes
in `--mnemonic`. The mode follows from which side is fixed. Always print the effective keyspace
(and, for joint, the explicit product) before running.

---

## 12. Roadmap — from here

Browser milestones M0–M9 of the original plan are **done and shipped** (see §0 and `REPORT.md` /
git history). The forward work is the **CLI performance backend** and a few browser follow-ups.

**CLI (the main thrust — topmost performance on GPUs/clusters):**
- **C1 — Oracle & vectors.** Python oracle: mnemonic(+passphrase, NFKD) → seed → BIP32 → derive
  `m/{44,49,84,86}'/…` → all four address types + account xpub, plus the **Electrum** scheme. Gate
  vs official BIP39 (Trezor)/BIP32 vectors, reference-wallet address triples, and Electrum's own
  vectors. (The browser's gated JS is a second cross-check.)
- **C2 — CPU crack, byte-exact.** Fork bip38rxcrack's skeleton; PBKDF2-HMAC-SHA512, BIP32 CKDpriv,
  secp256k1 (reuse), bech32/bech32m (new), taproot tweak; **4–8-way AVX2 SHA-512**. Selftests vs C1.
- **C3 — CPU crack end-to-end** (passphrase mode, single path, `-D`, `-p`, `--address`/`--xpub`) —
  the minimum lovable CLI; recovers a known test wallet from a regex.
- **C4 — Path fan-out + inference + xpub EC-free fast path** (§5/§3).
- **C5 — Words + Joint modes** (10 BIP39 languages, checksum pre-filter + last-word shortcut,
  `{{ }}`/missing/typo; nested-product sharding).
- **C6 — GPU Tier A/B** (OpenCL + CUDA PBKDF2-SHA512 kernel; byte-exact gate; then GPU BIP32 chain +
  on-device chain-code compare for xpub — the headline number).
- **C7 — Multi-GPU + cluster** (§10.1): `--gpus N` fork/exec-per-GPU, `--range`/`--count`
  cross-machine, lowest-index merge, exit codes — the reason the CLI exists.
- **C8 — Tier C (GPU secp256k1)** for address targets, only if cluster address-throughput demands it.
- **C9 — Electrum scheme in the CLI** (already in the browser); old (v1) Electrum seeds if wanted.

**Browser follow-ups (parked, Kiko's call):**
- **Last-word checksum shortcut** wired end-to-end (pattern-shape detection).
- **Old (v1) Electrum seeds** and **2fa** derivation (fetched reference in scratchpad; parked).
- **Opt-in balance check** (needs an explorer API), **model.js prose i18n** finish.
- **Publish/deploy** + create a public repo — *only when Kiko asks.*

---

## 13. Correctness discipline (unchanged — THE LAW)

- **Oracle first, always.** No C path ships without a byte-exact selftest vs the oracle; no GPU
  kernel without a byte-exact check vs the CPU reference. Gate against the **reference**, never a
  sibling model.
- **Published vectors** anchor the oracle: BIP39 (Trezor) seed/xprv, BIP32 derivation, known
  (mnemonic, passphrase, path)→address triples for 44/49/84/86 incl. taproot, and Electrum's own
  vectors.
- **Confirm every hit fully** (re-derive end-to-end) before printing success.

---

## 14. The UI / regex-authoring problem (what makes the tool usable)

The tool is only practical because the user *knows something*; a cold full-charset search is out of
reach — say so plainly. The browser already embodies this (and the CLI mirrors it):

- **Estimate first** — cardinality, checksum-survival (exact or sampled, labeled), path multiplier,
  a **calibrated** rate (benchmarked on *this* machine), and **time-to-exhaust** as the honest
  planning number; a **9-tier verdict**.
- **Coach, don't just refuse** — name the levers that move the number: *provide an account xpub*
  (removes secp256k1 from the loop), *tighten a segment*, *lower `--gap`*, *remember one more word*
  (÷2048), *reduce the path fan-out* — and, at the top end, **route the job to the CLI/cluster.**
- **`--dry-run N`** / the dry-run modal — *see* what the pattern actually generates before a long run.
- **A pattern cookbook** (§ README quick-reference) — teach by example.
- **Frame it honestly:** "for a *remembered* secret's shape, not blind brute-force." Motto on the
  banner.

---

## 15. Electrum & other schemes

**Electrum v2 is shipped** in the browser (§2.2 KDF salt `"electrum"`, seed-version validity
`HMAC-SHA512("Seed version", normalize(phrase))` prefix `01`/`100`/`101`/`102`, root-based
derivation, its own normalization) and gated byte-exact vs Electrum's own vectors
(`test/test_electrum.js`); joint + GPU parity done. **Parked:** old (v1) Electrum seeds
(`stretch_key` 100k-SHA256 + type-2 uncompressed P2PKH — reference vector fetched) and 2fa
derivation. The "seed scheme" is effectively pluggable now; new schemes slot in behind the same
estimate→crack→gate flow.

---

## 16. Open questions / decisions when CLI work starts

- **NFKD in C:** bundle a compact normalizer vs. utf8proc vs. ASCII-only-with-warning (recommend a
  small bundled NFKD — the browser proves it's needed).
- **Reuse vs. vendor** of bip38rxcrack code: copy the few files initially; consider a shared
  `libbtccrypto` later.
- **Default path-plan** for an address-only target: infer purpose from format, `account 0, change 0,
  gap 1` — confirm the tight default.
- **Cluster coordination:** shell launcher + `--range` (like bip38rxcrack) first; a real
  coordinator/swarm (Tier 3) only if the scale demands it.
- **When to publish** and under what repo/license.

---

*Build under the same supervise/byte-exact model as bip38rxcrack; keep the family's conventions and
its motto: **cracking hard is alright, but smart is better.***
