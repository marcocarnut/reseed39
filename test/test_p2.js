#!/usr/bin/env node
// P2 verification: the estimator MODEL (checksum-survival, path multiplier,
// joint product, ETA, verdict) on top of the librxe->wasm counts. Every count
// still comes from the wasm core; only the model math is exercised here.
//
// Run:  node test/test_p2.js

const fs = require('fs');
const path = require('path');
const { loadRxeCore } = require('../wasm/rxecore_api.js');
const { makeValidator } = require('../estimator/bip39.js');
const {
  estimate, checksumSurvival, pathMultiplier, humanTime, humanCount,
} = require('../estimator/model.js');

let pass = 0, fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log('  ok   ' + msg); }
  else { fail++; console.log('  FAIL ' + msg); }
}
function eq(a, b, msg) { ok(a === b, `${msg}  (got ${a}, want ${b})`); }
function approx(a, b, tol, msg) { ok(Math.abs(a - b) <= tol, `${msg}  (got ${a}, want ~${b}+-${tol})`); }

(async () => {
  const rxe = await loadRxeCore();
  const words = fs.readFileSync(path.join(__dirname, '..', 'data', 'english.txt'), 'utf8')
    .trim().split(/\r?\n/);
  const validator = makeValidator(words);
  // BIP39 words mode uses a [:bip39-en:] dictionary in librxe:
  rxe.registerDict('bip39-en', words);

  /* ---------------- pathMultiplier ---------------- */
  console.log('\n[path multiplier]');
  {
    const pm = pathMultiplier({ purposes: ['bip84'], accounts: 1, change: 1, gap: 1 }, 'address');
    eq(pm.value, 1, 'single path,gap1 => 1');
    const pm2 = pathMultiplier({ purposes: ['bip44', 'bip49', 'bip84', 'bip86'], accounts: 3, change: 2, gap: 5 }, 'address');
    eq(pm2.value, 4 * 3 * 2 * 5, '4 paths x 3 acct x 2 change x 5 gap = 120');
    const pmx = pathMultiplier({ purposes: ['bip44', 'bip49', 'bip84', 'bip86'], accounts: 3, change: 2, gap: 5 }, 'xpub');
    eq(pmx.value, 4 * 3, 'xpub collapses to purposes x accounts = 12');
    ok(pmx.collapsed === true, 'xpub multiplier flagged collapsed');
  }

  /* ---------------- checksum-survival (exact) ---------------- */
  console.log('\n[checksum survival: exact]');
  {
    // A 12-word pattern with the last word ranging over the whole list:
    // 11 fixed "abandon" + [:bip39-en:]. Raw = 2048; valid ones = those whose
    // last word makes the checksum correct. For all-"abandon" prefix the only
    // valid 12th word is "about" (the canonical zero-entropy mnemonic) -> and
    // any other word whose low bits happen to match; BIP39 guarantees exactly
    // 2048/16 = 128 valid completions of a fixed 11-word prefix.
    const pat = '(abandon ){11}[:bip39-en:]';
    const set = rxe.parse(pat);
    eq(set.cardinality(), 2048n, 'raw set = 2048 last-word choices');
    const s = checksumSurvival(set, validator, { exactThreshold: 5000 });
    eq(s.method, 'exact', 'small set => exact enumeration');
    eq(s.raw, 2048n, 'raw reported = 2048');
    eq(s.validCount, 128n, '2048/16 = 128 checksum-valid completions');
    eq(s.wordCount, 12, 'word count detected = 12');
    approx(s.fraction, 1 / 16, 1e-9, 'exact fraction = 1/16');
    approx(s.theoreticalFraction, 1 / 16, 1e-9, '12-word theory = 1/16');
    set.free();
  }

  /* ---------------- checksum-survival (sampled) ---------------- */
  console.log('\n[checksum survival: sampled]');
  {
    // Two unknown word positions => 2048^2 ~ 4.19M raw, over the exact
    // threshold, so the model samples. Fraction must land near 1/16.
    const pat = '(abandon ){10}[:bip39-en:] [:bip39-en:]';
    const set = rxe.parse(pat);
    eq(set.cardinality(), (2048n * 2048n), 'raw set = 2048^2');
    const s = checksumSurvival(set, validator, { exactThreshold: 200000, sampleSize: 8000 });
    eq(s.method, 'sampled', 'large set => sampled');
    ok(s.sampleSize >= 4000, `drew a real sample (${s.sampleSize})`);
    approx(s.fraction, 1 / 16, 0.02, 'sampled fraction ~ 1/16 (within 0.02)');
    // extrapolated valid count near raw/16 = 262144
    const expect = Number(2048n * 2048n) / 16;
    approx(Number(s.validCount) / expect, 1.0, 0.15, 'extrapolated valid count ~ raw/16');
    set.free();
  }

  /* ---------------- full estimate: PASSPHRASE mode ---------------- */
  console.log('\n[estimate: passphrase mode]');
  {
    // known mnemonic, passphrase shape "Correct" + optional Horse + 0-2 digits
    const r = estimate({
      passphrasePattern: 'Correct(horse|Horse)?[0-9]{0,2}',
      mnemonicKnown: true,
      targetType: 'address',
      path: { purposes: ['bip84'], accounts: 1, change: 1, gap: 1 },
      backend: 'cpu', cores: 8,
    }, { rxe, validator });
    eq(r.mode, 'passphrase', 'mode = passphrase');
    // cardinality: "Correct" x {"", horse, Horse} x {"",0..9,00..99}
    //   suffix count = 1 + 10 + 100 = 111 ; middle = 3  => 333
    eq(r.passphrase.cardinality, 333n, 'passphrase set = 333');
    eq(r.totalCandidates, 333n, 'total candidates = 333 (path mult 1)');
    ok(r.verdict === 'green', 'tiny keyspace => green');
    ok(/no-op/.test(r.notes.join(' ')), 'notes: checksum is a no-op in passphrase mode');
    ok(r.eta && !r.eta.calibrated, 'ETA present and labelled not-calibrated');
    r._sets.passSet.free();
  }

  /* ---------------- full estimate: WORDS mode ---------------- */
  console.log('\n[estimate: words mode]');
  {
    const r = estimate({
      mnemonicPattern: '(abandon ){11}[:bip39-en:]',
      mnemonicKnown: false,
      targetType: 'xpub',
      path: { purposes: ['bip44', 'bip84'], accounts: 1 },
      backend: 'cpu', cores: 4,
      exactThreshold: 5000,
    }, { rxe, validator });
    eq(r.mode, 'words', 'mode = words');
    eq(r.validMnemonicCount, 128n, 'valid mnemonics = 128 (2048/16)');
    // xpub path mult = purposes(2) x accounts(1) = 2
    eq(r.pathPlan.value, 2, 'xpub path multiplier = 2');
    eq(r.totalCandidates, 256n, 'total = 128 x 2 = 256');
    ok(r.eta.ecSeconds === 0, 'xpub target => zero EC time');
    r._sets.wordsSet.free();
  }

  /* ---------------- full estimate: JOINT mode (product) ---------------- */
  console.log('\n[estimate: joint mode]');
  {
    const r = estimate({
      mnemonicPattern: '(abandon ){11}[:bip39-en:]',   // 128 valid
      passphrasePattern: '[a-z]{4}',                    // 456976
      mnemonicKnown: false,
      targetType: 'xpub',
      path: { purposes: ['bip84'], accounts: 1 },
      backend: 'gpu',
      exactThreshold: 5000,
    }, { rxe, validator });
    eq(r.mode, 'joint', 'mode = joint');
    eq(r.dim1, 128n * 456976n, 'dim1 = validWords x passphrase (product)');
    eq(r.totalCandidates, 128n * 456976n, 'total = product x pathmult(1)');
    ok(r.notes.some(l => /PRODUCT/.test(l)), 'joint mode always notes the product keyspace');
    r._sets.wordsSet.free();
    r._sets.passSet.free();
  }

  /* ---------------- unbounded pattern => red ---------------- */
  console.log('\n[estimate: unbounded]');
  {
    const r = estimate({
      passphrasePattern: '[a-z]+',   // infinite
      mnemonicKnown: true,
      targetType: 'address',
      path: { purposes: ['bip84'] },
      backend: 'cpu', cores: 1,
    }, { rxe, validator });
    ok(r.unbounded === true, 'unbounded flagged');
    eq(r.verdict, 'red', 'unbounded => red verdict');
    eq(r.totalCandidatesHuman, 'unbounded', 'total shown as unbounded');
    if (r._sets.passSet) r._sets.passSet.free();
  }

  /* ---------------- verdict escalation + ETA scaling ---------------- */
  console.log('\n[estimate: verdict escalation]');
  {
    // Big passphrase keyspace on CPU should push to yellow/red.
    const r = estimate({
      passphrasePattern: '[a-zA-Z0-9]{8}',  // 62^8 ~ 2.18e14
      mnemonicKnown: true,
      targetType: 'xpub',
      path: { purposes: ['bip84'], accounts: 1 },
      backend: 'cpu', cores: 8,
    }, { rxe, validator });
    ok(r.totalCandidates > 10n ** 13n, 'huge keyspace (62^8)');
    eq(r.verdict, 'red', 'years+ on CPU => red');
    ok(r.narrowingLevers.length > 0, 'red => narrowing levers offered');
    // ETA sanity: 62^8 / (3000*8) seconds is ~ 2.9e8 s ~ 9 years
    approx(r.eta.exhaustSeconds / (Number(62n ** 8n) / (3000 * 8)), 1.0, 0.01, 'ETA = seeds/(kdf*cores)');
    r._sets.passSet.free();
  }

  /* ---------------- calibration hook ---------------- */
  console.log('\n[calibration hook]');
  {
    const r = estimate({
      passphrasePattern: '[a-z]{4}',
      mnemonicKnown: true,
      targetType: 'xpub',
      path: { purposes: ['bip84'] },
      backend: 'cpu', cores: 1,
      calibration: { source: 'measured on box (test)', cpu: { kdfPerCore: 1000 } },
    }, { rxe, validator });
    ok(r.eta.calibrated === true, 'calibration flips calibrated=true');
    approx(r.eta.exhaustSeconds, 456976 / 1000, 1, 'uses injected 1000/s rate');
    r._sets.passSet.free();
  }

  /* ---------------- humanTime / humanCount ---------------- */
  console.log('\n[formatting]');
  {
    eq(humanTime(0.4), '<1 s', 'sub-second');
    eq(humanTime(90), '1.5 minutes', '90s => 1.5 minutes');
    eq(humanTime(3600 * 25), '1 day', '25h => ~1 day');
    ok(/e14$/.test(humanCount(62n ** 8n)), '62^8 formatted as e14');
    eq(humanCount(333n), '333', 'small count plain');
    eq(humanCount(12345n), '12,345', 'thousands grouped');
  }

  console.log(`\n==== P2: ${pass} passed, ${fail} failed ====`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('EXCEPTION', e); process.exit(2); });
