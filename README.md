# bip39rxcrack — BIP39 keyspace / effort estimator (web/JS first)

> *Cracking hard is alright, but smart is better.*

A client-side **effort calculator** for BIP39 wallet recovery. You describe the *shape* of what
you half-remember — a passphrase regex and/or a mnemonic pattern — plus the *type* of target you
have (a Bitcoin **address** or, better, an **xpub**), and it tells you **how big the search is**
and **roughly how long it would take**, with a green / yellow / red verdict and concrete ways to
narrow it down.

It is the front door to `bip39rxcrack` (the cracker comes later): *estimate first, crack second.*

**It handles no secrets.** Only pattern *shapes* and the target *type* ever enter the page —
never real words, passphrases, or addresses — which is why it is safe as a static client-side page.

## Why an estimator at all

BIP39 has **no embedded check**: a mnemonic + passphrase *derives* keys but contains nothing to
test a guess against, so you must supply an external target. And the keyspace can explode
(especially in *joint* mode, a product of two patterns). The estimator stops hopeless searches
before they start and shows which lever actually shrinks the number.

## What it computes

- **Keyspace cardinality** and a **dry-run sample** straight from `librxe` (compiled to
  WebAssembly — the *same* enumeration core the native CLI will link, so they can’t drift).
- **Checksum-survival** for word patterns — the fraction of candidate mnemonics that are valid
  BIP39 (1/16 for 12-word, 1/256 for 24-word). **Exact** when the set is small enough to
  enumerate, **sampled** otherwise; it always tells you which.
- **Path-plan multiplier** (paths × accounts × change × gap); an **xpub** target collapses it and
  removes elliptic-curve math from the hot loop entirely — the single biggest speed lever.
- **Joint-mode product** (checksum-valid words × passphrase set).
- An **ETA** and a **green/yellow/red verdict** — the rate constants are **assumed placeholders,
  clearly labelled pre-calibration**; a calibration hook is ready for real measured rates.

## Run it

```
# tests (uses emsdk's bundled node):
. /root/emsdk/emsdk_env.sh
node test/test_p1.js     # librxe->wasm counts + unrank  (22/22)
node test/test_p2.js     # estimator model               (46/46)

# the page (static; loopback only):
python3 -m http.server 8899 --bind 127.0.0.1
# open http://127.0.0.1:8899/estimator/index.html
```

The page: pick a **common case** on the left (or start blank), edit the **rxe regex**, choose
**address vs xpub** and a derivation plan, and watch the keyspace, verdict, ETA and a live sample
update. A **Dictionaries** tab lets you register a `[:name:]` wordlist to reference in patterns
(the official BIP39 English list is pre-loaded as `[:bip39-en:]`).

## Layout

```
wasm/        librxe -> WebAssembly core (rxe_wasm.c shim, built rxecore.{js,wasm}, dual-mode API)
estimator/   bip39.js (checksum validator) · model.js (the one estimator model) · index.html (UI)
data/        english.txt (official BIP39 wordlist)
test/        test_p1.js · test_p2.js
```

## Status

Estimator only (this branch, `estimator-v0`): P1 wasm core, P2 model, P3 page, P4 docs — all
node/browser-verified. **No cracking crypto yet** and **ETA is pre-calibration.** See `REPORT.md`
for exactly what’s verified (with numbers) and what’s stubbed, and `PLAN.md` for the full design.
