#!/usr/bin/env node
// Gate the browser BIP39/BIP32 crypto against official vectors (SHA-512 KAT,
// BIP39 Trezor vector, BIP32 test vector 1). The xpub-target crack rests on this.
const C = require('../estimator/bip39crypto.js');
let pass=0, fail=0;
const ok=(c,m)=>{ if(c){pass++;console.log('  ok   '+m);} else {fail++;console.log('  FAIL '+m);} };
const eqh=(got,want,m)=>ok(got===want, `${m}\n        got  ${got}\n        want ${want}`);

// 1) SHA-512 known-answer
eqh(C.toHex(C.sha512(C.utf8('abc'))),
  'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
  'SHA-512("abc")');
eqh(C.toHex(C.sha512(C.utf8(''))),
  'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
  'SHA-512("")');

// 2) BIP39 official vector (English, passphrase "TREZOR")
const mn='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed=C.mnemonicToSeed(mn,'TREZOR');
eqh(C.toHex(seed),
  'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
  'BIP39 seed(abandon…about,"TREZOR")');

// 3) BIP32 test vector 1  (seed 000102…0f)
const bseed=C.fromHex('000102030405060708090a0b0c0d0e0f');
const m=C.seedToMaster(bseed);
eqh(C.toHex(C.ser256(m.k)), 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', 'BIP32 m priv');
eqh(C.toHex(m.c),           '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508', 'BIP32 m chaincode');
const m0h=C.ckdHardened(m, 0x80000000);
eqh(C.toHex(C.ser256(m0h.k)), 'edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea', "BIP32 m/0' priv");
eqh(C.toHex(m0h.c),           '47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141', "BIP32 m/0' chaincode");

// 4) base58check + extended-key decode round-trip (BIP32 vector 1 root xprv)
const xprv='xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';
const dec=C.decodeXpub(xprv);
eqh(C.toHex(dec.chainCode), '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508', 'xprv decode chaincode == master c');
eqh(C.toHex(dec.key), '00'+'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', 'xprv decode key == 00||master priv');
eqh(C.b58checkEncode(C.b58checkDecode(xprv)), xprv, 'base58check round-trip');

console.log(`\n==== crypto: ${pass} passed, ${fail} failed ====`);

// 5) END-TO-END: secp256k1-FREE xpub passphrase crack.
// Known mnemonic + unknown passphrase; target = the account node's chain code
// (what an account xpub carries). Enumerate candidates, compare chain codes.
(function(){
  const known='legal winner thank year wave sausage worth useful legal winner thank yellow';
  const realPass='swordfish7';
  const targetCC = C.accountNode(C.mnemonicToSeed(known, realPass), 84).c;  // BIP84 m/84'/0'/0'
  const candidates=['swordfish5','hunter2','swordfish9','swordfish7','Tr3zor'];
  let found=null;
  for (const cand of candidates){
    const cc = C.accountNode(C.mnemonicToSeed(known, cand), 84).c;
    if (C.eq(cc, targetCC)) { found=cand; break; }
  }
  ok(found===realPass, `e2e xpub crack: recovered passphrase "${realPass}" via chain-code compare (no EC) — got ${found}`);
})();

console.log(`\n==== with e2e: ${pass} passed, ${fail} failed ====`);
process.exit(fail?1:0);
