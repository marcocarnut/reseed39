// bip39crypto.js -- BIP39 seed + BIP32 hardened derivation + xpub chain-code
// compare, pure JS (browser + node). This is the correctness reference for the
// in-browser cracker (Batch 2): the xpub-target path is secp256k1-FREE --
// hardened derivation uses the parent PRIVATE key, so the account node's chain
// code is reached with only SHA-512/HMAC + a mod-n add. Compare that 32-byte
// chain code to the target xpub's and you've cracked it with zero elliptic curve.
//
// SHA-512 here is a clear BigInt implementation -- the CORRECTNESS reference,
// gated against the official BIP39/BIP32 vectors. The fast paths (Uint32-pair JS
// for the CPU cracker, WGSL for the GPU) will be gated byte-exact against THIS.
'use strict';

/* ------------------------------- SHA-512 -------------------------------- */
const M64 = (1n << 64n) - 1n;
const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M64;
const shr  = (x, n) => x >> n;
const K512 = [
  0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,
  0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,
  0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,
  0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,
  0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,
  0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,
  0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,
  0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,
  0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,
  0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n];
const H512_0 = [
  0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n];

// SHA-512 of a Uint8Array -> Uint8Array(64). BigInt REFERENCE (slow, gated-against).
function _sha512Big(bytes) {
  const l = bytes.length;
  const bitLen = BigInt(l) * 8n;
  // pad: 0x80, zeros to 112 mod 128, then 16-byte big-endian length
  const padLen = ((112 - (l + 1) % 128) + 128) % 128;
  const total = l + 1 + padLen + 16;
  const m = new Uint8Array(total);
  m.set(bytes); m[l] = 0x80;
  for (let i = 0; i < 16; i++) m[total - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
  const H = H512_0.slice();
  const W = new Array(80);
  for (let off = 0; off < total; off += 128) {
    for (let i = 0; i < 16; i++) {
      let w = 0n;
      for (let j = 0; j < 8; j++) w = (w << 8n) | BigInt(m[off + i * 8 + j]);
      W[i] = w;
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr(W[i-15],1n) ^ rotr(W[i-15],8n) ^ shr(W[i-15],7n);
      const s1 = rotr(W[i-2],19n) ^ rotr(W[i-2],61n) ^ shr(W[i-2],6n);
      W[i] = (W[i-16] + s0 + W[i-7] + s1) & M64;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr(e,14n) ^ rotr(e,18n) ^ rotr(e,41n);
      const ch = (e & f) ^ ((e ^ M64) & g);
      const t1 = (h + S1 + ch + K512[i] + W[i]) & M64;
      const S0 = rotr(a,28n) ^ rotr(a,34n) ^ rotr(a,39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & M64;
      h=g; g=f; f=e; e=(d + t1) & M64; d=c; c=b; b=a; a=(t1 + t2) & M64;
    }
    H[0]=(H[0]+a)&M64; H[1]=(H[1]+b)&M64; H[2]=(H[2]+c)&M64; H[3]=(H[3]+d)&M64;
    H[4]=(H[4]+e)&M64; H[5]=(H[5]+f)&M64; H[6]=(H[6]+g)&M64; H[7]=(H[7]+h)&M64;
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) for (let j = 0; j < 8; j++)
    out[i*8 + j] = Number((H[i] >> BigInt(8 * (7 - j))) & 0xffn);
  return out;
}

/* --------------- fast SHA-512 (Uint32 hi/lo; gated vs BigInt) ------------ *
 * Constants are DERIVED from the gated BigInt K512/H512_0 above (no retyping).
 * ~1-2 orders of magnitude faster than the BigInt reference; byte-exact to it.  */
const _KH = Uint32Array.from(K512, k => Number((k >> 32n) & 0xffffffffn));
const _KL = Uint32Array.from(K512, k => Number(k & 0xffffffffn));
const _IH = Uint32Array.from(H512_0, k => Number((k >> 32n) & 0xffffffffn));
const _ILo = Uint32Array.from(H512_0, k => Number(k & 0xffffffffn));
const _WH = new Uint32Array(80), _WL = new Uint32Array(80);

function sha512(bytes) {
  const l = bytes.length;
  const padLen = ((112 - (l + 1) % 128) + 128) % 128;
  const total = l + 1 + padLen + 16;
  const m = new Uint8Array(total);
  m.set(bytes); m[l] = 0x80;
  const bl = BigInt(l) * 8n;
  for (let i = 0; i < 16; i++) m[total - 1 - i] = Number((bl >> BigInt(8 * i)) & 0xffn);
  let h0h=_IH[0],h0l=_ILo[0], h1h=_IH[1],h1l=_ILo[1], h2h=_IH[2],h2l=_ILo[2], h3h=_IH[3],h3l=_ILo[3],
      h4h=_IH[4],h4l=_ILo[4], h5h=_IH[5],h5l=_ILo[5], h6h=_IH[6],h6l=_ILo[6], h7h=_IH[7],h7l=_ILo[7];
  const WH=_WH, WL=_WL;
  for (let off = 0; off < total; off += 128) {
    for (let i = 0; i < 16; i++) {
      const j = off + i*8;
      WH[i] = (m[j]<<24)|(m[j+1]<<16)|(m[j+2]<<8)|m[j+3];
      WL[i] = (m[j+4]<<24)|(m[j+5]<<16)|(m[j+6]<<8)|m[j+7];
    }
    for (let i = 16; i < 80; i++) {
      const x1h=WH[i-15], x1l=WL[i-15];
      // sigma0 = rotr(1)^rotr(8)^shr(7)
      const s0h = ((x1h>>>1)|(x1l<<31)) ^ ((x1h>>>8)|(x1l<<24)) ^ (x1h>>>7);
      const s0l = ((x1l>>>1)|(x1h<<31)) ^ ((x1l>>>8)|(x1h<<24)) ^ ((x1l>>>7)|(x1h<<25));
      const x2h=WH[i-2], x2l=WL[i-2];
      // sigma1 = rotr(19)^rotr(61)^shr(6)   (61 -> m=29 cross form)
      const s1h = ((x2h>>>19)|(x2l<<13)) ^ ((x2l>>>29)|(x2h<<3)) ^ (x2h>>>6);
      const s1l = ((x2l>>>19)|(x2h<<13)) ^ ((x2h>>>29)|(x2l<<3)) ^ ((x2l>>>6)|(x2h<<26));
      // W[i] = W[i-16] + s0 + W[i-7] + s1   (64-bit add via lo carry)
      const a16h=WH[i-16],a16l=WL[i-16], a7h=WH[i-7],a7l=WL[i-7];
      let lo = (a16l>>>0)+(s0l>>>0); let hi = (a16h+s0h+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      let lo2 = lo+(a7l>>>0); hi = (hi+a7h+(lo2>=0x100000000?1:0))>>>0; lo2>>>=0;
      let lo3 = lo2+(s1l>>>0); hi = (hi+s1h+(lo3>=0x100000000?1:0))>>>0; lo3>>>=0;
      WH[i]=hi; WL[i]=lo3>>>0;
    }
    let ah=h0h,al=h0l, bh=h1h,bl=h1l, ch=h2h,cl=h2l, dh=h3h,dl=h3l,
        eh=h4h,el=h4l, fh=h5h,fl=h5l, gh=h6h,gl=h6l, hh=h7h,hl=h7l;
    for (let i = 0; i < 80; i++) {
      // S1 = rotr(e,14)^rotr(e,18)^rotr(e,41)   (41 -> m=9)
      const S1h = ((eh>>>14)|(el<<18)) ^ ((eh>>>18)|(el<<14)) ^ ((el>>>9)|(eh<<23));
      const S1l = ((el>>>14)|(eh<<18)) ^ ((el>>>18)|(eh<<14)) ^ ((eh>>>9)|(el<<23));
      const chh = (eh & fh) ^ (~eh & gh);
      const chl = (el & fl) ^ (~el & gl);
      // S0 = rotr(a,28)^rotr(a,34)^rotr(a,39)   (34 -> m=2, 39 -> m=7)
      const S0h = ((ah>>>28)|(al<<4)) ^ ((al>>>2)|(ah<<30)) ^ ((al>>>7)|(ah<<25));
      const S0l = ((al>>>28)|(ah<<4)) ^ ((ah>>>2)|(al<<30)) ^ ((ah>>>7)|(al<<25));
      const majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      const majl = (al & bl) ^ (al & cl) ^ (bl & cl);
      // t1 = h + S1 + ch + K[i] + W[i]
      let lo=(hl>>>0)+(S1l>>>0); let hi=(hh+S1h+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      lo=lo+(chl>>>0); hi=(hi+chh+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      lo=lo+(_KL[i]>>>0); hi=(hi+_KH[i]+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      lo=lo+(WL[i]>>>0); hi=(hi+WH[i]+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      const t1h=hi, t1l=lo>>>0;
      // t2 = S0 + maj
      let lo2=(S0l>>>0)+(majl>>>0); let hi2=(S0h+majh+(lo2>=0x100000000?1:0))>>>0; lo2>>>=0;
      const t2h=hi2, t2l=lo2>>>0;
      hh=gh;hl=gl; gh=fh;gl=fl; fh=eh;fl=el;
      // e = d + t1
      let elo=(dl>>>0)+(t1l>>>0); eh=(dh+t1h+(elo>=0x100000000?1:0))>>>0; el=elo>>>0;
      dh=ch;dl=cl; ch=bh;cl=bl; bh=ah;bl=al;
      // a = t1 + t2
      let alo=(t1l>>>0)+(t2l>>>0); ah=(t1h+t2h+(alo>=0x100000000?1:0))>>>0; al=alo>>>0;
    }
    let lo;
    lo=(h0l>>>0)+(al>>>0); h0h=(h0h+ah+(lo>=0x100000000?1:0))>>>0; h0l=lo>>>0;
    lo=(h1l>>>0)+(bl>>>0); h1h=(h1h+bh+(lo>=0x100000000?1:0))>>>0; h1l=lo>>>0;
    lo=(h2l>>>0)+(cl>>>0); h2h=(h2h+ch+(lo>=0x100000000?1:0))>>>0; h2l=lo>>>0;
    lo=(h3l>>>0)+(dl>>>0); h3h=(h3h+dh+(lo>=0x100000000?1:0))>>>0; h3l=lo>>>0;
    lo=(h4l>>>0)+(el>>>0); h4h=(h4h+eh+(lo>=0x100000000?1:0))>>>0; h4l=lo>>>0;
    lo=(h5l>>>0)+(fl>>>0); h5h=(h5h+fh+(lo>=0x100000000?1:0))>>>0; h5l=lo>>>0;
    lo=(h6l>>>0)+(gl>>>0); h6h=(h6h+gh+(lo>=0x100000000?1:0))>>>0; h6l=lo>>>0;
    lo=(h7l>>>0)+(hl>>>0); h7h=(h7h+hh+(lo>=0x100000000?1:0))>>>0; h7l=lo>>>0;
  }
  const out = new Uint8Array(64);
  const put = (h,l,o)=>{ out[o]=(h>>>24)&255;out[o+1]=(h>>>16)&255;out[o+2]=(h>>>8)&255;out[o+3]=h&255;
                         out[o+4]=(l>>>24)&255;out[o+5]=(l>>>16)&255;out[o+6]=(l>>>8)&255;out[o+7]=l&255; };
  put(h0h,h0l,0);put(h1h,h1l,8);put(h2h,h2l,16);put(h3h,h3l,24);
  put(h4h,h4l,32);put(h5h,h5l,40);put(h6h,h6l,48);put(h7h,h7l,56);
  return out;
}
// The BigInt reference is kept (renamed) so the fast one can be gated against it.
function sha512Big(bytes) { return _sha512Big(bytes); }

/* --------- HMAC midstates (for the GPU: fixed key -> precompute ipad/opad) --- *
 * Compress ONE 128-byte block into a SHA-512 state (BigInt; host-side, run twice
 * per crack -- perf irrelevant). hmacMidstates(key) returns the SHA-512 state
 * after absorbing the ipad/opad blocks, as hi/lo u32 tables for the WGSL kernel,
 * so each per-lane HMAC is a single from-state block. Gated: GPU HMAC using these
 * must equal hmacSha512 (the full, already-gated reference).                     */
function _sha512CompressBig(H, block /* Uint8Array(128) */) {
  const W = new Array(80);
  for (let i = 0; i < 16; i++) { let w = 0n; for (let j = 0; j < 8; j++) w = (w << 8n) | BigInt(block[i*8+j]); W[i] = w; }
  for (let i = 16; i < 80; i++) {
    const s0 = rotr(W[i-15],1n) ^ rotr(W[i-15],8n) ^ shr(W[i-15],7n);
    const s1 = rotr(W[i-2],19n) ^ rotr(W[i-2],61n) ^ shr(W[i-2],6n);
    W[i] = (W[i-16] + s0 + W[i-7] + s1) & M64;
  }
  let [a,b,c,d,e,f,g,h] = H;
  for (let i = 0; i < 80; i++) {
    const S1 = rotr(e,14n)^rotr(e,18n)^rotr(e,41n);
    const ch = (e & f) ^ ((e ^ M64) & g);
    const t1 = (h + S1 + ch + K512[i] + W[i]) & M64;
    const S0 = rotr(a,28n)^rotr(a,34n)^rotr(a,39n);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) & M64;
    h=g; g=f; f=e; e=(d+t1)&M64; d=c; c=b; b=a; a=(t1+t2)&M64;
  }
  return [(H[0]+a)&M64,(H[1]+b)&M64,(H[2]+c)&M64,(H[3]+d)&M64,(H[4]+e)&M64,(H[5]+f)&M64,(H[6]+g)&M64,(H[7]+h)&M64];
}
function _stateToU32(state8) {   // -> Uint32Array(16), hi,lo interleaved
  const o = new Uint32Array(16);
  for (let i = 0; i < 8; i++) { o[i*2] = Number((state8[i] >> 32n) & 0xffffffffn); o[i*2+1] = Number(state8[i] & 0xffffffffn); }
  return o;
}
function hmacMidstates(key /* Uint8Array */) {
  let k = key; if (k.length > 128) k = sha512(k);
  const kp = new Uint8Array(128); kp.set(k);
  const ip = new Uint8Array(128), op = new Uint8Array(128);
  for (let i = 0; i < 128; i++) { ip[i] = kp[i] ^ 0x36; op[i] = kp[i] ^ 0x5c; }
  return { ipad: _stateToU32(_sha512CompressBig(H512_0, ip)),
           opad: _stateToU32(_sha512CompressBig(H512_0, op)) };
}
function _u32ToState(u32){ const s=[]; for(let i=0;i<8;i++) s.push((BigInt(u32[i*2])<<32n)|BigInt(u32[i*2+1])); return s; }
// Continue SHA-512 from `stateU32` (hi/lo) absorbing ONE more block whose data is
// `msg[0..msgLen)` (msgLen<=111), given `prior` bytes already hashed. Returns the
// 64-byte digest. This is exactly what the WGSL kernel does per HMAC half.
function sha512FromState1blk(stateU32, msg, msgLen, prior){
  const blk=new Uint8Array(128);
  for(let i=0;i<msgLen;i++) blk[i]=msg[i];
  blk[msgLen]=0x80;
  const bl=BigInt(prior+msgLen)*8n;
  for(let i=0;i<16;i++) blk[127-i]=Number((bl>>BigInt(8*i))&0xffn);
  const st=_sha512CompressBig(_u32ToState(stateU32), blk);
  const out=new Uint8Array(64);
  for(let i=0;i<8;i++) for(let j=0;j<8;j++) out[i*8+j]=Number((st[i]>>BigInt(8*(7-j)))&0xffn);
  return out;
}
// HMAC + PBKDF2 via precomputed midstates (the GPU decomposition; salt+4<=111).
function hmacViaMid(mid, msg){ return sha512FromState1blk(mid.opad, sha512FromState1blk(mid.ipad, msg, msg.length, 128), 64, 128); }
function pbkdf2ViaMid(mid, salt){
  let u = sha512FromState1blk(mid.ipad, concat(salt, Uint8Array.of(0,0,0,1)), salt.length+4, 128);
  u = sha512FromState1blk(mid.opad, u, 64, 128);
  const t = u.slice();
  for (let i=1;i<2048;i++){ u=sha512FromState1blk(mid.ipad,u,64,128); u=sha512FromState1blk(mid.opad,u,64,128); for(let j=0;j<64;j++) t[j]^=u[j]; }
  return t;
}

/* ------------------------------- HMAC/PBKDF2 ---------------------------- */
function hmacSha512(key, msg) {           // key,msg: Uint8Array -> Uint8Array(64)
  const B = 128;
  let k = key;
  if (k.length > B) k = sha512(k);
  const kpad = new Uint8Array(B); kpad.set(k);
  const ipad = new Uint8Array(B), opad = new Uint8Array(B);
  for (let i = 0; i < B; i++) { ipad[i] = kpad[i] ^ 0x36; opad[i] = kpad[i] ^ 0x5c; }
  const inner = sha512(concat(ipad, msg));
  return sha512(concat(opad, inner));
}
// PBKDF2-HMAC-SHA512, dkLen a multiple handled generally; BIP39 uses dkLen=64 (1 block).
function pbkdf2Sha512(password, salt, iterations, dkLen) {
  const hLen = 64, blocks = Math.ceil(dkLen / hLen);
  const out = new Uint8Array(blocks * hLen);
  for (let b = 1; b <= blocks; b++) {
    const bi = new Uint8Array(4); bi[0]=(b>>>24)&255; bi[1]=(b>>>16)&255; bi[2]=(b>>>8)&255; bi[3]=b&255;
    let u = hmacSha512(password, concat(salt, bi));
    const t = u.slice();
    for (let i = 1; i < iterations; i++) { u = hmacSha512(password, u); for (let j=0;j<hLen;j++) t[j] ^= u[j]; }
    out.set(t, (b-1)*hLen);
  }
  return out.slice(0, dkLen);
}

/* ------------------------------- BIP39 seed ----------------------------- */
const _enc = (typeof TextEncoder !== 'undefined') ? new TextEncoder() : null;
function utf8(s){ return _enc ? _enc.encode(s) : Uint8Array.from(Buffer.from(s,'utf8')); }
function nfkd(s){ return s.normalize('NFKD'); }
// BIP39: seed = PBKDF2(NFKD(mnemonic), "mnemonic"+NFKD(passphrase), 2048, 64).
function mnemonicToSeed(mnemonic, passphrase='') {
  return pbkdf2Sha512(utf8(nfkd(mnemonic)), utf8('mnemonic' + nfkd(passphrase)), 2048, 64);
}

/* ------------------------------- BIP32 ---------------------------------- */
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
function bytesToBig(b){ let x=0n; for (let i=0;i<b.length;i++) x=(x<<8n)|BigInt(b[i]); return x; }
function ser256(x){ const o=new Uint8Array(32); for(let i=31;i>=0;i--){o[i]=Number(x&0xffn);x>>=8n;} return o; }
function ser32(i){ return Uint8Array.of((i>>>24)&255,(i>>>16)&255,(i>>>8)&255,i&255); }
const HARD = 0x80000000;

// master node from seed: {k: BigInt priv, c: Uint8Array(32) chaincode}
function seedToMaster(seed){
  const I = hmacSha512(utf8('Bitcoin seed'), seed);
  return { k: bytesToBig(I.slice(0,32)), c: I.slice(32,64) };
}
// hardened CKDpriv (index already includes the 0x80000000 bit). No EC.
function ckdHardened(par, index){
  const data = concat(Uint8Array.of(0x00), ser256(par.k), ser32(index >>> 0));
  const I = hmacSha512(par.c, data);
  const IL = bytesToBig(I.slice(0,32));
  const k = (IL + par.k) % SECP_N;       // parse256(IL) < n assumed (holds w/ prob ~1)
  return { k, c: I.slice(32,64) };
}
// derive m / a' / b' / c' ... (all hardened) from seed; returns the final node.
function deriveHardenedPath(seed, hardIndices){
  let node = seedToMaster(seed);
  for (const i of hardIndices) node = ckdHardened(node, (i + HARD) >>> 0);
  return node;
}
// The account node m/purpose'/coin'/account' -- its chain code is what an account
// xpub carries, reachable with NO elliptic curve. purpose: 44|49|84|86, coin 0.
function accountNode(seed, purpose, account=0, coin=0){
  return deriveHardenedPath(seed, [purpose, coin, account]);
}

/* ------------------------------- base58check ---------------------------- */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const _sha256 = (typeof BIP39 !== 'undefined') ? BIP39.sha256
              : (typeof require === 'function') ? require('./bip39.js').sha256 : null;
function sha256d(b){ return _sha256(_sha256(b)); }
function b58decode(str){
  let x = 0n; for (const ch of str){ const v = B58.indexOf(ch); if (v<0) throw new Error('bad base58'); x = x*58n + BigInt(v); }
  const bytes=[]; while (x>0n){ bytes.unshift(Number(x & 0xffn)); x >>= 8n; }
  for (let i=0;i<str.length && str[i]==='1';i++) bytes.unshift(0);
  return Uint8Array.from(bytes);
}
function b58encode(bytes){
  let x = bytesToBig(bytes); let s='';
  while (x>0n){ const r=Number(x%58n); s=B58[r]+s; x/=58n; }
  for (let i=0;i<bytes.length && bytes[i]===0;i++) s='1'+s;
  return s;
}
function b58checkDecode(str){
  const raw=b58decode(str); const payload=raw.slice(0,-4), chk=raw.slice(-4);
  const h=sha256d(payload); for(let i=0;i<4;i++) if(h[i]!==chk[i]) throw new Error('bad base58check checksum');
  return payload;
}
function b58checkEncode(payload){
  const h=sha256d(payload); return b58encode(concat(payload, h.slice(0,4)));
}
// Decode an xpub/ypub/zpub -> {version, depth, fingerprint, childNumber, chainCode(32), key(33)}.
function decodeXpub(str){
  const p=b58checkDecode(str);
  if (p.length!==78) throw new Error('extended key must be 78 bytes, got '+p.length);
  return { version: bytesToBig(p.slice(0,4)), depth: p[4], fingerprint: p.slice(5,9),
           childNumber: bytesToBig(p.slice(9,13)), chainCode: p.slice(13,45), key: p.slice(45,78) };
}

/* ------------------------------- helpers -------------------------------- */
function concat(...arrs){ let n=0; for(const a of arrs) n+=a.length; const o=new Uint8Array(n); let k=0; for(const a of arrs){o.set(a,k);k+=a.length;} return o; }
function toHex(b){ let s=''; for(let i=0;i<b.length;i++) s+=b[i].toString(16).padStart(2,'0'); return s; }
function fromHex(h){ const o=new Uint8Array(h.length/2); for(let i=0;i<o.length;i++) o[i]=parseInt(h.substr(i*2,2),16); return o; }
function eq(a,b){ if(a.length!==b.length) return false; for(let i=0;i<a.length;i++) if(a[i]!==b[i]) return false; return true; }

const _exports = {
  sha512, sha512Big, hmacSha512, pbkdf2Sha512, mnemonicToSeed,
  seedToMaster, ckdHardened, deriveHardenedPath, accountNode, SECP_N, ser256,
  b58decode, b58encode, b58checkDecode, b58checkEncode, decodeXpub,
  toHex, fromHex, concat, eq, utf8, nfkd,
  // SHA-512 K/H0 as hi/lo u32 tables (for the WGSL kernel; same gated constants).
  gpuK: { hi: _KH, lo: _KL }, gpuH0: { hi: _IH, lo: _ILo },
  // GPU HMAC midstate decomposition (host precompute + node gate).
  hmacMidstates, sha512FromState1blk, hmacViaMid, pbkdf2ViaMid,
};
if (typeof module !== 'undefined' && module.exports) module.exports = _exports;
if (typeof window !== 'undefined') window.BIP39Crypto = _exports;
