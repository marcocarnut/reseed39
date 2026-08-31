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

/* ===================== ADDRESS-TARGET crack crypto ===================== *
 * secp256k1 + non-hardened derive + HASH160 + bech32/bech32m + all four
 * address types, gated against known vectors. Cross-checks the whole
 * seed -> derive -> pubkey -> program -> address pipeline end to end.        */
console.log('\n---- address-target crypto ----');

// 6) secp256k1: privToPub against BIP32 test vector 1 master pubkey.
eqh(C.toHex(C.privToPub(m.k)),
  '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',
  'secp256k1 privToPub == BIP32 vector-1 master pubkey');

// 7) RIPEMD-160 known-answer (empty + "abc").
eqh(C.toHex(C.ripemd160(C.utf8(''))),    '9c1185a5c5e9fc54612808977ee8f548b2258d31', 'RIPEMD-160("")');
eqh(C.toHex(C.ripemd160(C.utf8('abc'))), '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc', 'RIPEMD-160("abc")');

// 8) bech32/bech32m round-trip via BIP173/BIP350 test vectors.
eqh(C.bech32Decode('A1LQFN3A')?.spec, 'bech32m', 'bech32m sample decodes');
eqh(C.segwitEncode('bc', 0, C.fromHex('751e76e8199196d454941c45d1b3a323f1433bd6')),
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'segwit v0 encode (BIP173 vector)');

// 9) THE address vectors: mnemonic "abandon…about", NO passphrase, m/p'/0'/0'/0/0.
const av='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const aseed=C.mnemonicToSeed(av,'');
const mkAddr=(purpose)=>{ const pub=C.privToPub(C.addressNode(aseed,purpose,0,0,0,0).k); const tg=C.pubToTarget(pub,purpose);
  if (tg.type==='p2pkh') return C.b58encode(C.concat(Uint8Array.of(0x00),tg.program, sfx(0x00,tg.program)));
  if (tg.type==='p2sh')  return C.b58encode(C.concat(Uint8Array.of(0x05),tg.program, sfx(0x05,tg.program)));
  if (tg.type==='p2wpkh')return C.segwitEncode('bc',0,tg.program);
  if (tg.type==='p2tr')  return C.segwitEncode('bc',1,tg.program); };
function sfx(ver,prog){ const _sha=require('../estimator/bip39.js').sha256; const p=C.concat(Uint8Array.of(ver),prog); return _sha(_sha(p)).slice(0,4); }
eqh(mkAddr(84), 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', 'BIP84 m/84\'/0\'/0\'/0/0');
eqh(mkAddr(86), 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 'BIP86 m/86\'/0\'/0\'/0/0');
eqh(mkAddr(44), '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA', 'BIP44 m/44\'/0\'/0\'/0/0');
eqh(mkAddr(49), '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf', 'BIP49 m/49\'/0\'/0\'/0/0');

// 10) decodeAddress -> {type, program} matches what pubToTarget builds.
for (const [purpose,addr] of [[84,'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'],
                              [86,'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'],
                              [44,'1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA'],
                              [49,'37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf']]){
  const d=C.decodeAddress(addr);
  const built=C.pubToTarget(C.privToPub(C.addressNode(aseed,purpose,0,0,0,0).k), purpose);
  ok(d.type===built.type && C.eq(d.program, built.program), `decodeAddress == pubToTarget for BIP${purpose} (${d.type})`);
  // encodeAddress is the inverse of decodeAddress (round-trips to the exact string).
  ok(C.encodeAddress(d)===addr, `encodeAddress round-trips BIP${purpose} (${d.type})`);
}

// 11) CUSTOM PATH TEMPLATE: deriveTemplate must reproduce the trusted BIP44-family
//     derivation byte-exact for the canonical templates, and programForType must
//     match pubToTarget. This validates the template engine against known-good code.
console.log('\n---- custom path templates ----');
for (const [purpose,type] of [[44,'p2pkh'],[49,'p2sh'],[84,'p2wpkh'],[86,'p2tr']]){
  const tmpl=`m/${purpose}'/0'/0'/{change}/{index}`;
  let good=true;
  for (const [ch,ix] of [[0,0],[0,1],[1,0],[1,5]]){
    const node=C.deriveTemplate(aseed, tmpl, {change:ch,index:ix});
    const viaTmpl=C.programForType(C.privToPub(node.k), type);
    const viaStd =C.addressTarget(aseed, purpose, 0, 0, ch, ix);
    if(!(viaTmpl.type===viaStd.type && C.eq(viaTmpl.program, viaStd.program))) good=false;
  }
  ok(good, `deriveTemplate+programForType == addressTarget for BIP${purpose} (${type})`);
}
// hardened marker actually matters: m/0'/0/0 (Breadwallet-shape) != m/0'/0'/0
{
  const k=(t)=>C.ser256(C.deriveTemplate(aseed,t,{}).k);
  ok(!C.eq(k("m/0'/0/0"), k("m/0'/0'/0")), "hardened marker matters: m/0'/0/0 != m/0'/0'/0");
  ok(C.eq(k("m/0h/0/0"), k("m/0'/0/0")), "h and ' hardened markers equivalent");
}
// parse validation rejects garbage
for (const bad of ['x/0/0','m/0/-1','m/0/1a','m/']){ let threw=false; try{ C.parsePathTemplate(bad); }catch(e){ threw=true; } ok(threw, `parsePathTemplate rejects "${bad}"`); }
// customMatch: plant a Breadwallet-shape P2PKH target at m/0'/1/3 and recover it.
{
  const tmpl=C.parsePathTemplate("m/0'/{change}/{index}");
  const planted=C.programForType(C.privToPub(C.deriveTemplate(aseed,tmpl,{change:1,index:3}).k),'p2pkh');
  const hit=C.customMatch(aseed, tmpl, planted, {changes:[0,1], gap:5});
  ok(hit && hit.change===1 && hit.index===3, "customMatch finds m/0'/1/3 (Breadwallet-shape)");
  ok(C.customMatch(aseed, tmpl, planted, {changes:[0], gap:3})===null, "customMatch misses when the range excludes the hit");
}

// 11) END-TO-END address-target crack: unknown passphrase, known BIP84 address.
(function(){
  const known='legal winner thank year wave sausage worth useful legal winner thank yellow';
  const realPass='swordfish7';
  const seedR=C.mnemonicToSeed(known, realPass);
  const targetAddr=C.segwitEncode('bc',0,C.pubToTarget(C.privToPub(C.addressNode(seedR,84,0,0,0,0).k),84).program);
  const target=C.decodeAddress(targetAddr);
  const candidates=['swordfish5','hunter2','swordfish9','swordfish7','Tr3zor'];
  let found=null;
  for (const cand of candidates){
    const s=C.mnemonicToSeed(known, cand);
    const built=C.pubToTarget(C.privToPub(C.addressNode(s,84,0,0,0,0).k),84);
    if (built.type===target.type && C.eq(built.program, target.program)){ found=cand; break; }
  }
  ok(found===realPass, `e2e address crack: recovered "${realPass}" via P2WPKH program compare — got ${found}`);
})();

// 12) privToPubBatch (Montgomery batch inversion) == privToPub elementwise.
(function(){
  const ks=[]; for(let i=1;i<=500;i++) ks.push((C.SECP_N - BigInt(i)*104729n) % C.SECP_N);
  const b=C.privToPubBatch(ks); let good=true;
  for(let i=0;i<ks.length;i++) if(C.toHex(b[i])!==C.toHex(C.privToPub(ks[i]))) good=false;
  ok(good, `privToPubBatch == privToPub over ${ks.length} keys (batch inversion)`);
})();

console.log(`\n==== FINAL: ${pass} passed, ${fail} failed ====`);
process.exit(fail?1:0);
