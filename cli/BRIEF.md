# bip39rxcrack (CUDA CLI) — box-agent kickoff brief

You are the **box-agent** building `bip39rxcrack`, a native CUDA seed cracker, on the
gpuhub dual-RTX-5090 box. Read `cli/PLAN.md` (in the `reseed39` repo) in full first — it is
the design. This brief is *how to start*.

## The collaboration law (non-negotiable)
- **Correctness authority is the byte-exact browser reference in `reseed39`**
  (`estimator/bip39crypto.js`, `estimator/bip39.js`, and the `test/test_*.js` vectors) plus
  the published BIP39/BIP32/BIP86 test vectors. **Gate every kernel against those, never
  against a sibling GPU model.**
- **You build and measure on the box; you commit BRANCH-ONLY.** The laptop session
  **rxe-b5** is the correctness authority and **sole git integrator** — it reviews your
  branch, gates it, and fast-forward-merges to `main`. Same model as bip38rxcrack.
- **No cracking code until the crypto gates pass.** Phase 1 is gates only.

## Box / environment
- SSH (port is reassigned on every box restart — reconfirm with Kiko): current
  `ssh -p 48851 root@connect.singapore-a.gpuhub.com`.
- If git/ssh auth fails after a reboot: `export SSH_AUTH_SOCK=/run/user/1000/keyring/ssh`.
- **The box currently has ONE GPU** (scaled down for billing). **Architect for N GPUs
  anyway** (see PLAN §7): fork/exec one `CUDA_VISIBLE_DEVICES`-pinned child per GPU, shard
  by index range, lowest-index-wins merge, exit codes 0/1/2/3. Exercise it with `-G 1` now;
  never hard-code a single device.
- Reuse the **bip38rxcrack** CUDA scaffolding you already know (nvrtc runtime compile,
  Makefile shape, multi-GPU fork/exec, `--range`/`--count`, `multigpu.sh`, librxe as an
  external dep `RXE_DIR=../rxe`). Its CUDA secp256k1 is the reference for the later address
  path.

## Repos to clone on the box
- `reseed39` — the oracle (crypto + vectors) **and** this plan/brief (`cli/`).
- `rxe` — librxe + rxejit (`RXE_DIR=../rxe`); the on-GPU `{{n!}}`/`{{k}}` unrank math and
  index-range sharding are your enumeration reference.
- `bip39rxcrack` — the new standalone repo (Kiko creates the empty GitHub repo; you push
  your first scaffold to a branch, rxe-b5 establishes `main`).

## Phase 1 — crypto gates FIRST (do this, nothing else, until it's green)
Build standalone CUDA kernels and a harness that diffs their output against the browser
reference / known vectors. Stage them:
1. **SHA-512** — vs the SHA-512 KAT.
2. **PBKDF2-HMAC-SHA512(2048) seed** == `mnemonicToSeed` over random mnemonics × lengths,
   including the 24-word (>128-byte key) pre-hash boundary. (Blueprint: `pbkdf2.wgsl` /
   `pbkdf2_words.wgsl` / `sha512.wgsl`.)
3. **BIP39 checksum** (SHA-256, top `cs` bits) == `sha256_1blk_h0` / `makeValidator`, over
   many random entropies × the 12/15/18/21/24-word sizes.
4. **BIP32 master + hardened CKDpriv (EC-FREE) → account chain code** == `accountNode`, vs
   BIP32 vector-1 and random seeds.

Deliverable: a `make gate` that prints PASS/FAIL per stage with counts, zero mismatches.
**Report the gate output to rxe-b5 before writing any enumeration/crack loop.**

## Phase 2 (only after Phase 1 is merged) — xpub crack, single GPU, self-enumerate
The **GPU enumerates its own candidates** from its global index (PLAN §3) — do NOT port the
browser's CPU-sweep hybrid. Kernel: `odometer digits → checksum sieve → PBKDF2 → hardened
derive → 32-byte chain-code compare`. Recover a planted xpub seed end-to-end and confirm
the **found index/path is byte-identical** to what (re)seed39 finds for the same pattern
(e.g. the "known words, unknown order" example). The BIP39 word's 11-bit index **is** the
odometer digit — work on digits, never rendered strings.

## Parity contract (keep it in mind from v1 — PLAN §13)
The eventual input format is the **(re)seed39 share-state JSON** (`--job`/`--link`): same
rxe grammar (incl. `[:bip39-en:]` and the `[:Nth:]` family), same target/purpose rules.
For v1, recognize the fields; for anything unimplemented (address target, Electrum),
**reject with a clear message — never silently ignore or misinterpret a field.**

## First actions
1. Confirm the box + GPU (`nvidia-smi`) and the CUDA toolchain version.
2. Clone `reseed39` + `rxe`; read `cli/PLAN.md`.
3. Stand up the Phase-1 gate harness. Report results to rxe-b5. Stop there.
