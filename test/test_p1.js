#!/usr/bin/env node
// P1 verification: librxe->wasm cardinality + unrank, checked against
// hand-computed truths and unrank/rank round-trips. This proves the wasm core
// reports the SAME counts librxe computes natively (THE DRIFT RULE).
//
// Run:  node test/test_p1.js   (uses emsdk's node, or any node >= 16)

const { loadRxeCore } = require('../wasm/rxecore_api.js');

let pass = 0, fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log('  ok   ' + msg); }
  else { fail++; console.log('  FAIL ' + msg); }
}
function eq(a, b, msg) { ok(a === b, `${msg}  (got ${a}, want ${b})`); }

(async () => {
  const rxe = await loadRxeCore();

  // A small dictionary so we can exercise the [:name:] mechanism.
  rxe.registerDict('col', ['red', 'green', 'blue']);
  rxe.registerDict('bip39mini', ['cat', 'dog', 'fish', 'bird']);

  // ---- cardinality against hand-computed truths ----
  console.log('\n[cardinality]');
  const cases = [
    ['[a-z]{4}', 456976n],                 // 26^4
    ['(cat|dog)[0-9]{2}', 200n],           // 2 * 100
    ['(a|bb|ccc)', 3n],                    // explicit alternation
    ['[0-9]{3}', 1000n],
    ['(a|b|c){{2}}', 3n],                  // C(3,2) unordered choose
    ['[a-z]{{3}}', 2600n],                 // C(26,3)
    ['(cat|dog|fish){{3!}}', 6n],          // P(3,3) = 3! reorder of known words
    ['(a|b|c){{2!}}', 6n],                 // P(3,2) ordered
    [':col:-dict', 9n, () => rxe.parse('[:col:]{2}')],   // 3^2 via dictionary
    [':col:-choose', 3n, () => rxe.parse('[:col:]{{2}}')], // C(3,2) over dict words
    ['abc', 1n],                           // singleton
    ['(a|b|c|d|e){2}', 25n],
  ];
  for (const [pat, want, make] of cases) {
    const set = make ? make() : rxe.parse(pat);
    const got = set.cardinality();
    eq(got, want, `|${pat}| = ${want}`);
    set.free();
  }

  // ---- unrank: first / last members ----
  console.log('\n[unrank endpoints]');
  {
    const s = rxe.parse('[a-z]{4}');
    eq(s.unrank(0n), 'aaaa', '[a-z]{4} unrank(0)');
    eq(s.unrank(456975n), 'zzzz', '[a-z]{4} unrank(N-1)');
    ok(s.unrank(456976n) === null, '[a-z]{4} unrank(N) is out-of-range null');
    s.free();
  }
  {
    const s = rxe.parse('(cat|dog)[0-9]{2}');
    eq(s.unrank(0n), 'cat00', '(cat|dog)[0-9]{2} unrank(0)');
    eq(s.unrank(199n), 'dog99', '(cat|dog)[0-9]{2} unrank(199)');
    s.free();
  }

  // ---- unrank/rank round-trips (first, last, random) ----
  console.log('\n[round-trips]');
  for (const pat of ['[a-z]{4}', '(cat|dog)[0-9]{2}', '[0-9]{3}', '(a|b|c|d|e){2}']) {
    const s = rxe.parse(pat);
    const N = s.cardinality();
    const idxs = [0n, N - 1n];
    for (let k = 0; k < 5; k++) idxs.push(BigInt(Math.floor(Math.random() * Number(N))));
    let allgood = true;
    for (const i of idxs) {
      const member = s.unrank(i);
      const back = s.rank(member);
      if (member === null || back === null || back !== i) {
        allgood = false;
        console.log(`     mismatch at i=${i}: member=${member} rank=${back}`);
      }
    }
    ok(allgood, `${pat}: rank(unrank(i)) === i for endpoints + randoms`);
    s.free();
  }

  // ---- a dry-run sample listing (what the user would see) ----
  console.log('\n[sample: (cat|dog|fish){{3!}} first 6]');
  {
    const s = rxe.parse('(cat|dog|fish){{3!}}');
    const N = s.cardinality();
    const seen = new Set();
    for (let i = 0n; i < N; i++) { const m = s.unrank(i); seen.add(m); console.log('   ' + m); }
    eq(seen.size, 6, 'all 6 permutations distinct');
    s.free();
  }

  console.log(`\n==== P1: ${pass} passed, ${fail} failed ====`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('EXCEPTION', e); process.exit(2); });
