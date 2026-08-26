#!/usr/bin/env node
// Gate the Electrum v2 seed scheme byte-exact against Electrum's OWN published
// test vectors (spesmilo/electrum tests/test_mnemonic.py + test_wallet_vertical.py):
// KDF (salt "electrum"), seed-version type, and root/m-0' derivation -> address.
const C = require('../estimator/bip39crypto.js');
const E = require('../estimator/electrum.js');
let pass=0, fail=0;
const ok=(c,m)=>{ if(c){pass++;console.log('  ok   '+m);} else {fail++;console.log('  FAIL '+m);} };
const eqs=(got,want,m)=>ok(got===want, `${m}\n        got  ${got}\n        want ${want}`);

// 1) KDF: PBKDF2-HMAC-SHA512(normalize(mnemonic), "electrum"+normalize(pass), 2048, 64)
eqs(C.toHex(E.toSeed('foobar','none')),
  '741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5bb22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce',
  'seed(foobar, pass=none)');
const wild='wild father tree among universe such mobile favorite target dynamic credit identify';
eqs(C.toHex(E.toSeed(wild,'')),
  'aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756',
  'seed(wild father tree…, no pass)');
eqs(C.toHex(E.toSeed(wild,'Did you ever hear the tragedy of Darth Plagueis the Wise?')),
  '4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f',
  'seed(wild father tree…, with passphrase)');

// 2) seed-version type (HMAC "Seed version" prefix)
eqs(E.seedType(wild), 'segwit', 'seedType(wild…) = segwit (prefix 100)');
eqs(E.seedType('cycle rocket west magnet parrot shuffle foot correct salt library feed song'), 'standard', 'seedType(cycle…) = standard (prefix 01)');
eqs(E.seedType('bitter grass shiver impose acquire brush forget axis eager alone wine silver'), 'segwit', 'seedType(bitter…) = segwit');
ok(E.seedType('legal winner thank year wave sausage worth useful legal winner thank yellow')===null
   || E.seedType('legal winner thank year wave sausage worth useful legal winner thank yellow')!=='segwit',
   'a BIP39-valid phrase is not (necessarily) an Electrum segwit seed');

// 3) STANDARD (p2pkh): root m -> address m/0/0, and the root xpub chain code
{
  const s = E.toSeed('cycle rocket west magnet parrot shuffle foot correct salt library feed song','');
  eqs(E.address(s,'standard',0,0), '1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf', 'standard receiving[0] = 1NNk…owKRf');
  const xpub='xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U';
  ok(C.eq(C.decodeXpub(xpub).chainCode, E.accountNode(s,'standard').c), 'standard xpub chain code == accountNode(m).c');
}
// 4) SEGWIT (p2wpkh): node m/0' -> address m/0'/0/0 & m/0'/1/0, and the zpub chain code
{
  const s = E.toSeed('bitter grass shiver impose acquire brush forget axis eager alone wine silver','');
  eqs(E.address(s,'segwit',0,0), 'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af', 'segwit receiving[0] = bc1q3g5…h3af');
  eqs(E.address(s,'segwit',1,0), 'bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p', 'segwit change[0] = bc1qdy9…nx2p');
  const zpub='zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ';
  ok(C.eq(C.decodeXpub(zpub).chainCode, E.accountNode(s,'segwit').c), 'segwit zpub chain code == accountNode(m/0\').c');
}

console.log(`\n==== ELECTRUM: ${pass} passed, ${fail} failed ====`);
process.exit(fail? 1 : 0);
