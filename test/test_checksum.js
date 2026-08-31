#!/usr/bin/env node
// Gate the "generate valid" checksum path (bip39.js completeLastWord / complete
// / scaffoldWords) byte-exact against the checksum reference (isValid) and a
// brute-force over the full wordlist. THE LAW: no shortcut trusted without a
// byte-exact check vs the reference.
const fs = require('fs');
const B = require('../estimator/bip39.js');
const WORDS = fs.readFileSync(__dirname + '/../data/english.txt', 'utf8').trim().split(/\r?\n/);
const V = B.makeValidator(WORDS);
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ok   ' + m); } else { fail++; console.log('  FAIL ' + m); } };

// 1) IDEMPOTENCE: completing an already-valid mnemonic returns it unchanged.
const VALIDS = [
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',            // 12w
  'legal winner thank year wave sausage worth useful legal winner thank yellow',                              // 12w
  'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote',          // 24w
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art', // 24w
];
for (const m of VALIDS) {
  ok(V.isValid(m), 'precheck valid: ' + m.split(' ').length + 'w');
  ok(V.complete(m) === m, 'idempotent complete() on valid ' + m.split(' ').length + 'w');
}

// 2) SCAFFOLD SIZES + the size*stride=2048 invariant + stride representatives.
for (const [W, tok] of Object.entries(B.NTH_TOKENS)) {
  const w = +W, cs = B.csBitsFor(w), sc = B.scaffoldWords(WORDS, w);
  ok(sc.length === (1 << (11 - cs)), `[:${tok}:] size = ${1 << (11 - cs)} (CS=${cs})`);
  ok(sc.length * (1 << cs) === 2048, `[:${tok}:] size*stride = 2048`);
  ok(sc[0] === WORDS[0] && sc[1] === WORDS[1 << cs], `[:${tok}:] uses stride ${1 << cs} reps`);
}

// 3) SCAFFOLD CORRECTNESS: all-zero 23-word prefix, the 8 [:24th:] scaffold words
//    complete to the 8 checksum-valid final words == brute force over all 2048.
{
  const prefix23 = Array(23).fill('abandon');
  const sc = B.scaffoldWords(WORDS, 24);
  const generated = new Set();
  for (const w of sc) {
    const toks = prefix23.concat(w);
    const last = V.completeLastWord(toks);
    ok(last !== null, 'complete 24w scaffold candidate');
    toks[23] = last;
    ok(V.isValid(toks.join(' ')), 'generated 24w is checksum-valid (' + last + ')');
    generated.add(last);
  }
  // brute-force truth: every final word that makes the all-abandon-23 prefix valid
  const truth = new Set();
  for (let i = 0; i < 2048; i++) { const t = prefix23.concat(WORDS[i]); if (V.isValid(t.join(' '))) truth.add(WORDS[i]); }
  ok(truth.size === 8, 'brute force: exactly 8 valid 24th words for all-abandon prefix');
  ok(generated.size === 8 && [...truth].every(x => generated.has(x)), 'generate == brute force (24w, byte-exact set)');
  // the known zero-entropy answer
  ok(V.completeLastWord(Array(23).fill('abandon').concat(WORDS[0])) === 'art', 'all-zero 24w entropy -> "art"');
}

// 4) Same for a 12-word prefix: 128 valid last words, generate == brute force.
{
  const prefix11 = Array(11).fill('abandon');
  const sc = B.scaffoldWords(WORDS, 12);
  const generated = new Set(sc.map(w => V.completeLastWord(prefix11.concat(w))));
  const truth = new Set();
  for (let i = 0; i < 2048; i++) { const t = prefix11.concat(WORDS[i]); if (V.isValid(t.join(' '))) truth.add(WORDS[i]); }
  ok(truth.size === 128, 'brute force: exactly 128 valid 12th words for all-abandon prefix');
  ok(generated.size === 128 && [...truth].every(x => generated.has(x)), 'generate == brute force (12w, byte-exact set)');
  ok(V.completeLastWord(prefix11.concat(WORDS[0])) === 'about', 'all-zero 12w entropy -> "about"');
}

// 5) A varying MIDDLE word + scaffold last word: substitution uses full entropy,
//    so each middle choice yields its own valid completion (not one static set).
{
  const sc24 = B.scaffoldWords(WORDS, 24);
  const mkPrefix = (mid) => { const p = Array(23).fill('abandon'); p[5] = mid; return p; };
  const setA = new Set(sc24.map(w => V.completeLastWord(mkPrefix('zoo').concat(w))));
  const setB = new Set(sc24.map(w => V.completeLastWord(mkPrefix('able').concat(w))));
  for (const p of [['zoo', setA], ['able', setB]]) {
    for (const w of sc24) { const t = mkPrefix(p[0]).concat(V.completeLastWord(mkPrefix(p[0]).concat(w))); ok(V.isValid(t.join(' ')), `middle=${p[0]}: generated valid`); }
  }
  ok([...setA].some(x => !setB.has(x)), 'different middle word -> different valid last-word set (prefix-dependent)');
}

console.log(`\n==== CHECKSUM-GENERATE: ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
