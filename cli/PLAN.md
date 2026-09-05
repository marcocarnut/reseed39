# bip39rxcrack — CUDA CLI implementation plan

> *Cracking hard is alright, but smart is better.*

**Goal.** A native CLI seed cracker for BIP39 (and later Electrum) that takes an rxe
mnemonic/passphrase pattern + a public target (address or xpub), and searches the
keyspace on GPU. Primary target hardware: the **dual RTX 5090** gpuhub box (same box
that built the bip38 cracker). Correctness authority is the **byte-exact** browser
reference; performance is bounded by PBKDF2‑SHA512, not by candidate feeding — *if we
choose the right architecture*.

This plan distills everything learned building the browser tool (`estimator/`) and the
bip38 cracker, and answers the one question that decides the architecture:

> **If the GPU is ~100× the browser iGPU, can the CPU feed it fast enough?**

Short answer: **not with the browser's CPU‑sweep hybrid — but that's the wrong model
for a discrete GPU.** Make the GPU self‑enumerate (the rxejit model) and the feed
problem disappears. Details in §3 and §9.

---

## 1. What we already have (reuse, don't reinvent)

**From the browser (`estimator/`), all gated byte‑exact — these are the reference oracle:**
- `bip39crypto.js` — SHA‑512 (BigInt + fast Uint32), HMAC/PBKDF2‑SHA512(2048),
  `mnemonicToSeed` (NFKD), BIP32 master + **hardened CKDpriv (mod‑n, secp256k1‑FREE)**,
  `accountNode`, non‑hardened `ckdNormal`/`addressNode`, secp256k1 (field/Jacobian/**W=8
  fixed‑base comb**/BIP340 lift_x), RIPEMD‑160/hash160, bech32/bech32m, `pubToTarget`
  (BIP44 p2pkh / 49 p2sh‑p2wpkh / 84 p2wpkh / 86 p2tr incl. TapTweak), `decodeAddress`.
- `bip39.js` — `sha256_1blk_h0` (fast one‑block SHA‑256 checksum), `makeValidator`.
- `pbkdf2.wgsl` / `pbkdf2_words.wgsl` / `sha512.wgsl` — the WGSL kernels (per‑lane HMAC
  midstate, 2048‑loop). **These are the algorithm blueprints to port to CUDA.**
- `test/test_crypto.js` (26/26), `test/test_checksum.js`, `test/test_p2.js` (46/46),
  known BIP39/BIP32/BIP86 vectors — **the CLI must reproduce all of these.**

**From the bip38 cracker (`github.com/marcocarnut/bip38rxcrack`) — the CUDA scaffolding:**
- Multi‑GPU **fork/exec one CUDA_VISIBLE_DEVICES‑pinned child per GPU**, shard by index
  range, **lowest‑index‑wins** merge, exit codes 0/1/2/3, `multigpu.sh`/`--range`/`--count`.
  Reuse this pattern verbatim.
- CUDA **secp256k1** (point mult) for address verify — reuse for the address‑target path.
- **librxe as an external dep** (`RXE_DIR=../rxe`), links the ENUMERATOR (and, for the
  self‑enumerate path, the rxejit JIT).
- nvrtc runtime compile of the per‑pattern kernel.

**From librxe / rxejit (`../rxe`):**
- The **enumerator** (CPU odometer; `rxe_next` steps, `rxe_seek` pays a division once).
- **rxejit** — finite‑regex → per‑lane GPU kernel, with pluggable hash **sinks**, `{{n!}}`
  ordered‑perm and `{{k}}` combination unrank **on the GPU (u64 unrank)**, multi‑GPU
  sharding, `-G`. **This is the enumeration engine for the self‑enumerate architecture.**

---

## 2. The pipeline (per candidate)

```
odometer digit-indices  →  [BIP39 checksum sieve]  →  seed  →  derive  →  compare
   (11-bit word idxs)       SHA-256(entropy)[:cs]     PBKDF2   BIP32     to target
                            reject 255/256 (24w)      SHA512   +EC?
```

Cost profile (why the architecture works out):
- **Checksum sieve:** ~1 SHA‑256 block per candidate. Cheap. Rejects 255/256 (24w; the
  ratio is 2^cs: 12w 16×, 15w 32×, 18w 64×, 21w 128×, 24w 256×).
- **PBKDF2‑SHA512(2048):** ~4096 SHA‑512 blocks per *survivor*. **This dominates
  everything** — amortized ~16 SHA‑512 blocks per raw candidate at 24w. The whole tool
  is PBKDF2‑bound, exactly as it should be.
- **BIP32 derive:** master (1 HMAC‑SHA512) + a few hardened steps (SHA512). Tiny vs PBKDF2.
- **Compare:** xpub → 32‑byte chain‑code memcmp (**EC‑free**); address → secp256k1 k·G +
  hash160/bech32 program memcmp (EC — heavier, but still << PBKDF2).

**Key data-representation win:** the BIP39 word's 11‑bit index **is** the odometer digit
(when the dict is the canonical 2048 BIP39 list). The checksum and seed need *indices*,
not rendered strings. So the sink consumes **digits, never strings** — no render, no
re‑parse. (This is the "expose the odometer word‑indices" capability the browser notes
flagged as the missing lever; in the CLI we own the kernel, so we build on digits from
the start.)

---

## 3. Architecture decision: GPU self‑enumeration (primary)

The browser used a **hybrid**: CPU workers unrank + checksum‑filter, stream survivors to
the GPU for PBKDF2. That was a WebGPU‑era compromise (couldn't easily run the librxe
unrank on‑GPU; JS sweep was available). It is **CPU‑sweep‑bound**, and on a 100× GPU it
cannot keep up (§9). **Do not port the hybrid as the primary path.**

**Primary path — the rxejit model: the GPU enumerates its own candidates.** Each GPU
thread computes its candidate directly from its global index (unrank on‑device), runs the
whole pipeline, and reports hits. The CPU only hands out **index ranges** and collects
results. There is **no candidate transfer over PCIe**, so there is **no feed bottleneck** —
the GPU is PBKDF2‑bound and pegged near 100%.

Concretely: extend rxejit with a **BIP39 sink**. rxejit already gives us, on‑GPU and for
free: pattern→kernel compile, `{{n!}}`/`{{k}}` unranking (unknown order / combinations),
grid‑stride enumeration, multi‑GPU sharding, early‑exit on found. We write only the sink:
`digits → checksum sieve → PBKDF2 → BIP32 → compare`.

**Fallback path — host‑fed hybrid** for patterns rxejit can't compile to a
self‑enumerating kernel (huge external dictionaries, deeply nested combinatorics, custom
off‑list words). Here the CPU enumerates **packed digit tuples** (not strings) in big
batches, double‑buffered to the GPU. Even this is far lighter than the browser's model
(no string render, no per‑candidate JS↔wasm marshalling), but PCIe/CPU can bound it, so
it's the exception, not the rule. Mitigations if needed: pack digits tightly (≤ 2 bytes
each, or bit‑pack 11‑bit), big batches, `cudaMemcpyAsync` double‑buffer, split across the
two GPUs.

---

## 4. Two target paths

**xpub target — the fast lane (EC‑FREE).** Decode xpub → account chain code. Kernel does
PBKDF2 → BIP32 master → hardened derive to the account node (SHA‑512 only, mod‑n add) →
compare 32‑byte chain code. **No secp256k1 at all.** This is the flagship path; it's the
lightest and should hit the PBKDF2 ceiling. Mirror `accountNode` + the EC‑free CKDpriv
from `bip39crypto.js`.

**address target — needs secp256k1.** Decode address → {script type, program}. Kernel
does PBKDF2 → BIP32 → non‑hardened derive to the receive index → k·G (reuse the bip38
CUDA secp256k1, or port the W=8 fixed‑base comb) → script program (hash160 / bech32m /
BIP86 TapTweak) → memcmp. Scan `change × gap`. Only test purposes whose script type
matches the address (as the browser does). Heavier than xpub but still PBKDF2‑bound.

---

## 5. The `[:Nth:]` last‑word checksum construction (Kiko's dictionaries)

When the checksum‑bearing word (the **last** word of the phrase) is in the searched
region and the other words are concrete per candidate, **don't sweep‑and‑reject** — build
only the valid finals directly. For an N‑word phrase the last word = (free entropy bits) +
(cs checksum bits); enumerate the 2^(free) entropy possibilities, SHA‑256 the entropy,
append the cs checksum bits → the exact set of valid last‑word indices. Reduction = 2^cs
(12w 16× / 24w 256×), **zero rejection**.

Expose this as the **`[:12th:] … [:24th:]` dictionary family**: `[:Nth:]` in the final
token position means "the checksum‑valid last word of an N‑word phrase, given the other
N‑1 concretized words." In the self‑enumerate kernel this is a per‑thread construction
(unrank the free bits → SHA‑256 → assemble the index), not a static wordlist. Auto‑detect
where possible (variable token is the final position + others concrete) and also accept it
explicitly in the pattern.

**Boundary (be honest, enforce it):** this only works when the checksum word is in the
**free/searched** region. A *middle* unknown with a *fixed known* last word cannot be
constructed (SHA‑256 is one‑way; "fixing" would overwrite the known last word) → those
must still sieve. **Unknown‑order** (`{{12!}}`) likewise can't use it — every permutation
has a concrete last word that must be checked. So `[:Nth:]` is the "lost last word" turbo
path; the general sieve (fast on‑GPU SHA‑256) covers the rest.

---

## 6. checksum‑ON vs checksum‑OFF

- **checksum‑ON (default):** the GPU runs the SHA‑256 sieve as an **early reject** before
  PBKDF2. 255/256 die cheaply (24w). This is the common case and it's PBKDF2‑bound.
- **checksum‑OFF (off‑dictionary / custom words):** no sieve; every candidate is seeded.
  Also fully on‑GPU, just a bigger PBKDF2 load. Keep the toggle (`--no-checksum` /
  `require_checksum`), same semantics as the browser.

---

## 7. Multi‑GPU (dual RTX 5090)

Reuse the **bip38rxcrack** pattern exactly: **fork/exec one CUDA_VISIBLE_DEVICES‑pinned
child per GPU** (`-G [N]` defaults to all GPUs, `--device i` pins one), shard the global
index space by **range**, **lowest‑index‑wins** merge across children, exit codes 0/1/2/3.
`--range`/`--count` + a `multigpu.sh` for cross‑machine sharding. rxejit already shards by
candidate‑index range, so this composes cleanly. Expect ~1.97× on 2 GPUs (measured on the
bip38 side).

---

## 8. Correctness law (non‑negotiable)

**Gate every kernel byte‑exact against the browser reference, never a sibling model.**
- Port `test/test_crypto.js`, `test_checksum.js`, `test_p2.js` vectors to a C harness that
  diffs CUDA kernel outputs vs the known‑good values (SHA‑512 KAT, BIP39 Trezor vectors,
  BIP32 vector‑1, BIP86 taproot, the corrected BIP44 vector
  `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA`).
- Stage the pipeline: (a) SHA‑256 checksum == `sha256_1blk_h0`; (b) PBKDF2 seed ==
  `mnemonicToSeed` over random mnemonics × lengths (incl. 24‑word >128‑byte key pre‑hash);
  (c) chain code == `accountNode`; (d) address program == `pubToTarget` for all 4 types;
  (e) `[:Nth:]` valid‑set == the brute survivors (byte‑identical, just 2^cs fewer).
- End‑to‑end: recover the known planted seeds the browser recovers (e.g. the "known words,
  unknown order" example that found index 48,868,872) and confirm identical index/path.

The box‑agent builds/tests on the 5090s; **I remain the correctness authority + sole git
integrator** (same collab model as bip38: box‑agent commits branch‑only, I review,
ff‑merge, push).

---

## 9. The CPU‑feed question, answered with numbers

Rough PBKDF2‑HMAC‑SHA512(2048) throughput: a 4090 does low‑single‑digit MH/s at ~1k iters
(hashcat 12100); at 2048 iters ~1–2 MH/s. A 5090 ~1.3–1.5× → **~1–2M seeds/s per GPU,
~2–4M/s dual.** That's the *survivor* (post‑sieve) rate. At 24w / checksum‑ON (1/256
survive), the equivalent **raw candidate** throughput the enumerator must sustain is
**256× → ~0.5–1B candidates/s**.

- **Browser hybrid (CPU sweeps strings + checksum):** ~1.5M cand/s on 8 cores. Feeding
  0.5–1B/s is **~1000× short.** Confirmed dead end for a discrete GPU. This is why the
  browser GPU was under‑fed even at iGPU speed.
- **Host‑fed digits (fallback):** even at hundreds of M/s of odometer stepping, moving
  0.5–1B candidates/s × ~12–24 B is **6–24 GB/s over PCIe** — feasible on PCIe 4/5 but a
  real ceiling, and it burns CPU. Usable for un‑JIT‑able patterns, not the target.
- **GPU self‑enumerate (primary):** the candidate never leaves the GPU — each thread
  unranks its own index and runs the sieve on‑die. **The CPU only dispatches ranges;
  there is nothing to feed.** The GPU is PBKDF2‑bound at ~100% util. **This is the answer:
  the feed bottleneck is an artifact of the hybrid; self‑enumeration removes it.**

So: 100× GPU is fine **iff** we self‑enumerate. Chase the hybrid only for patterns the JIT
can't compile.

**One caveat from the thermal work:** discrete GPUs still throttle to a sustained plateau
under long load (we saw ~40s knees in the browser). A headless 5090 box has no calibration
UI, but the CLI's **ETA/`--loginterval` reporting should quote the sustained rate**, not
the cold peak — read the steady slope, same lesson as the estimator's Stage‑2 calibration.

---

## 10. Phasing / milestones

1. **Scaffold + gates.** New `cli/` (or a sibling repo, see §12). CUDA build reusing
   bip38rxcrack's Makefile/nvrtc/librxe‑external‑dep setup. Port the crypto **gates first**
   (SHA‑512, PBKDF2, BIP32 EC‑free, SHA‑256 checksum) as standalone CUDA kernels diffed vs
   the browser vectors. *No cracking yet — correctness first.*
2. **xpub path, single GPU, self‑enumerate.** BIP39 sink in rxejit (or a rxejit‑modeled
   CUDA kernel): digits → checksum sieve → PBKDF2 → hardened derive → chain‑code compare.
   Recover a planted xpub seed end‑to‑end, byte‑exact index vs the browser.
3. **`[:Nth:]` last‑word construction** (§5) + auto‑detect. Gate the valid‑set.
4. **address path** — add secp256k1 (reuse bip38 CUDA EC) + script programs + change/gap
   scan. Gate all 4 address types incl. taproot.
5. **Multi‑GPU** — fork/exec per‑GPU, range shard, lowest‑index merge, exit codes (§7).
   Measure dual‑5090 scaling.
6. **checksum‑OFF**, `--loginterval` CSV (match the browser log columns so we can diff),
   sustained‑rate ETA, and the perf write‑up.
7. **(later)** Electrum seeds (different KDF/prefix), hybrid fallback for un‑JIT‑able
   patterns.

## 11. Performance expectations

- **xpub, dual 5090:** target the PBKDF2 ceiling ~**2–4M seeds/s** → at 24w/checksum‑ON,
  ~**0.5–1B raw candidates/s** effective. That's ~**100–200×** the browser iGPU hybrid.
- **address:** lower (EC per candidate on the surviving path), but still PBKDF2‑dominated;
  expect within ~2–4× of the xpub path.
- Sanity check against the bip38 numbers (scrypt, ~1k cand/s on a 5090): PBKDF2‑SHA512 is
  vastly lighter than scrypt, so 3+ orders of magnitude more candidates/s is expected.

## 12. Open questions for Kiko (decide before the box‑agent starts)

1. **Repo:** `cli/` inside reseed39, or a **new standalone repo** (like bip38rxcrack got
   its own)? A sibling repo keeps the CUDA/build heft out of the web app and mirrors the
   bip38 split; I lean that way. It'd take librxe **and** the reseed39 crypto vectors as
   deps.
2. **rxejit BIP39 sink vs standalone CUDA kernel:** add the sink to rxejit (max reuse of
   its enumeration/multi‑GPU/`{{}}` machinery) vs a bip38‑style standalone kernel that
   borrows rxejit's unrank logic. I lean **rxejit sink** — but it needs the sink to see
   odometer **digits** (§2), which may be a small rxejit extension. Worth a spike first.
3. **xpub‑only v1?** The EC‑free xpub path is the cleanest, fastest, and covers Kiko's own
   use case; address can follow in phase 4. Ship xpub end‑to‑end first?
4. **Which box + access:** confirm the gpuhub dual‑5090 box, the (reassigned‑on‑restart)
   SSH port, and that the box‑agent commits branch‑only while I integrate (bip38 model).

---

*Correctness authority: the byte‑exact browser reference. Integration: single‑integrator,
box‑agent builds/measures. The seed never gets constructed on a machine you don't trust.*
