# AUTONOMOUS BRIEF — bip39rxcrack estimator (web/JS first)

You are an **autonomous background subagent** running on an always-on GPU box. The human
(Marco "Kiko" Carnut) and the integrator/correctness-authority Claude session are **away for
several hours**. You build **unattended**; your output will be **reviewed and integrated
later** — nothing you do here is final or user-facing yet. Work carefully, verify what you
can headlessly, and when in doubt STOP and write it down rather than guessing.

Read `PLAN.md` (same directory) in full before starting — especially §7.1 (joint mode),
§5 (paths), §9 (perf model), §14 (UI/estimator), and §12 (milestones M0–M2). This brief tells
you *what slice to build first and how*; PLAN.md is the authority on *what it means*.

---

## GOAL (this run)

Build the **BIP39 keyspace / effort ESTIMATOR, web/JS first** — a client-side page that takes
the *shape* of a search (a passphrase regex and/or a mnemonic pattern, plus a target *type*)
and reports how big the problem is and roughly how long it would take. Kiko's explicit call:
**do the JS estimator first, derive the CLI from it later** — "something useful earlier, and
less chance for them to drift."

The estimator handles **NO secrets** — only pattern *shapes* and the target *type* (address vs
xpub), never real words/passphrases/addresses. Keep it that way; it's why it's safe to be a
client-side page.

### THE DRIFT RULE (important)
The enumeration **cardinality and unrank MUST come from `librxe` compiled to WebAssembly** —
the *same* C library the future CLI will link natively. **Do NOT reimplement librxe's
set-counting/bijection in JavaScript.** Only the thin *estimator model* on top
(checksum-survival, path-plan multiplier, ETA/verdict) is new code — write it once, in one
place, so the later CLI can port it faithfully. This is the whole point of doing JS first.

---

## ENVIRONMENT

- librxe source is at `/root/rxe` (this is `RXE_DIR`). The native CLI `bip38rxcrack` at
  `/root/bip38rxcrack` links it — read its Makefile to see how librxe is built/linked natively,
  and read the librxe headers in `/root/rxe` to find the functions you need to export to wasm
  (regex compile/parse, **set cardinality/count**, **unrank(index)->string**, and the dict
  resolver / `[:name:]` mechanism and permutation `{{ }}` support if present).
- **You have root.** Install the emscripten stack yourself:
  ```
  apt-get update && apt-get install -y python3 xz-utils   # emsdk needs python3
  git clone https://github.com/emscripten-core/emsdk /root/emsdk
  cd /root/emsdk && ./emsdk install latest && ./emsdk activate latest
  . /root/emsdk/emsdk_env.sh          # per-shell; puts emcc + its bundled node on PATH
  emcc -v                              # verify (expect a working emcc + node)
  ```
  (A fresh install — no stale config to worry about on this box.) If `emcc` misbehaves, check
  that `emsdk_env.sh` set `EM_CONFIG` correctly.
- No GPU is needed. You verify the **logic** headlessly with **node** (emsdk bundles one).
- **You MAY install Chrome** (headless) if you want to functionally test the page and capture
  screenshots for Kiko's review — you are *not* building blind. It's optional; the numeric
  logic is fully verifiable in node regardless. (Chrome/headless, not full desktop.)
- CPU is shared with a niced bip38 build; you run at normal priority — just don't spawn
  runaway parallelism.
- **RESTART AWARENESS:** this box will be **restarted soon to add a second GPU**, which kills
  every process here — including you. **Your committed git branch is your ONLY durability.**
  Commit each working increment as soon as it's green (P1, then P2, then P3…), so a restart
  never costs more than a few minutes. Write `REPORT.md` early and keep updating it. After a
  restart you (a fresh instance) will be re-spawned to continue from the branch — leave it in a
  clean, resumable state at every checkpoint.

---

## DELIVERABLES — prioritized. Commit each increment on the branch as you go.

**P1 — librxe → wasm: cardinality + unrank, headless-verified.**
Build a small wasm module exporting at least: compile/parse a regex; total set cardinality
(as a 64-bit-safe value — use a string/BigInt bridge if counts exceed 2^53); unrank(i)->string.
Write a **node test** that checks counts against hand-computed truths, e.g.
`[a-z]{4}` = 456976; `(cat|dog)[0-9]{2}` = 200; a small explicit alternation; a small dict/perm
case if librxe exposes `[:name:]`/`{{ }}`. Unrank round-trips (first/last/random indices).
This proves the approach; it is the single most valuable increment.

**P2 — estimator model (new JS, one place), headless-tested.**
On top of the wasm counts, implement the model from PLAN §9/§14:
- total candidates = passphrase-set size and/or checksum-valid mnemonic-set size, × the
  **path-plan multiplier** (paths × accounts × change × gap), × product for **joint mode**.
- **checksum-survival**: exact when the mnemonic set is small enough to enumerate-and-count,
  else **sampled** — and the output must *say which* and show the fraction.
- **ETA**: needs a rate. There is **no browser here to calibrate**, so use the PLAN §9
  constants as **clearly-labeled placeholders** ("assumed, pre-calibration": CPU ~1–5K/s/core,
  GPU ~1e5–1e6/s; xpub target ⇒ no-EC/faster, address target ⇒ +EC/fan-out). Real calibration
  (browser JS-CPU + WebGPU) is a later step with Kiko — leave a clear hook for it.
- report **time-to-exhaust** as the planning number, note expected-to-hit ≈ half; emit a
  **green / yellow / red verdict** and, when poor, the **narrowing levers** text (provide an
  xpub, tighten a segment, drop gap, remember one more word ÷2048).
Unit-test this layer in node against a few worked examples.

**P3 — the HTML page.**
A single self-contained page (fine to inline JS/CSS; the wasm can be a sibling file or
base64-inlined) where the user enters a passphrase regex and/or mnemonic pattern, picks a
target type (address vs xpub) and path options, and **watches the keyspace and verdict update**
as they add constraints. Show the breakdown (set size, checksum fraction, path multiplier,
joint product), the ETA (labeled pre-calibration), the verdict, and a **dry-run sample** (first
N + random N via unrank) so they see what their pattern generates. You can't see it render —
keep the layout simple and robust; Kiko polishes visuals later.

**P4 — REPORT + README.**
Write `REPORT.md`: what you built, what's headless-verified (with the numbers), what's stubbed
(ETA calibration, UI polish), how to run/test, and any open questions or decisions for Kiko.
A short `README.md` for the estimator. Note anything you were unsure about.

---

## GUARDRAILS (hard limits — do not cross)

- Work in **`/root/bip39rxcrack`**. `git init` it; commit to a branch named **`estimator-v0`**
  (not master). Commit increments with message trailer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- **DO NOT push to any git remote. DO NOT publish anything anywhere. DO NOT open PRs.**
  The integrator will review and push after Kiko is back. (This box has no GitHub key anyway.)
- **Do not touch** `/root/bip38rxcrack`, `/root/rxe` (read-only reference — don't modify it),
  the bip38 work, the GPU, or any other repo/process.
- **No broad `pkill`/`killall`** — there may be other processes on this box; kill only exact
  PIDs you started.
- Keep changes inside `/root/bip39rxcrack` and the emsdk install. Nothing system-wide beyond
  the documented `apt-get install python3 xz-utils` + emsdk.
- If you hit anything irreversible, ambiguous, or outside this brief — **stop and write it in
  REPORT.md**; do not improvise around it.

## FALLBACK (only if librxe→wasm stalls)
Prefer the wasm core. But if getting librxe to compile/export under emcc eats more than ~45
min, ship an **interim pure-JS estimator prototype CLEARLY LABELED "throwaway — to be replaced
by the librxe-wasm core"** so there's something useful to review, then go back to the wasm
core. Never let the interim prototype masquerade as the real shared core.

## WHEN DONE (or when you've landed something substantial)
Write `REPORT.md`, make sure `estimator-v0` is committed, and send your parent (the box-agent)
a short status message: what's done, what's verified, what's left.
