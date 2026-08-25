#!/usr/bin/env node
/* spike/sha256-bench.js — how fast can we SHA-256 tiny inputs?
 *
 * WHY: the GPU derives ~11,000 BIP39 seeds/s. The host early-reject drops
 * mnemonics whose BIP39 checksum is invalid (SHA-256 over the 16-byte entropy,
 * check the top CS bits), and only 1/256 (12-word) survive. So to keep the GPU
 * fed the host filter must sustain ~11,000 * 256 = ~2.8 M SHA-256/s. The pure-JS
 * checksum SHA-256 seems too slow. This measures the real options on tiny
 * (16- and 32-byte) inputs — the only size the checksum ever hashes.
 *
 *   node spike/sha256-bench.js            # 16-byte (12-word) entropy
 *   node spike/sha256-bench.js 32         # 32-byte (24-word) entropy
 *
 * Nothing here is imported by the app; it only READS ../estimator/bip39.js.
 */
'use strict';
const path = require('path');
const crypto = require('crypto');

const TARGET = 11000 * 256;                       // ~2.8M/s to keep the GPU fed
const INLEN  = parseInt(process.argv[2] || '16', 10);   // entropy bytes (16=12w, 32=24w)
const SECONDS = 1.5;
const CORES = (() => { try { return require('os').availableParallelism(); }
                       catch { return require('os').cpus().length; } })();

/* the SHA-256 the estimator's checksum validator uses right now */
const compactSha256 = require(path.join(__dirname, '..', 'estimator', 'bip39.js')).sha256;

/* ---- allocation-free, single-block SHA-256 specialized for the checksum ----
 * Inputs <= 55 bytes fit in ONE 64-byte block (true for 16- and 32-byte
 * entropy). K is hoisted; the block + schedule buffers are reused across calls;
 * no per-call allocation. Returns h0 (the first output word) — the checksum only
 * needs the top CS<=8 bits, which live in h0, so we skip building the 32-byte
 * output entirely. (Return all 8 words if you ever need the full digest.) */
const K = new Int32Array([
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
const _blk = new Uint8Array(64);
const _w   = new Int32Array(64);
function sha256_1blk_h0(bytes) {           // bytes.length must be <= 55
  const l = bytes.length;
  _blk.fill(0);
  _blk.set(bytes);
  _blk[l] = 0x80;
  const bits = l * 8;                      // < 2^32 for l<=55 -> hi length words 0
  _blk[60] = (bits>>>24)&0xff; _blk[61] = (bits>>>16)&0xff;
  _blk[62] = (bits>>>8)&0xff;  _blk[63] =  bits&0xff;
  const w = _w;
  for (let i=0;i<16;i++)
    w[i]=(_blk[4*i]<<24)|(_blk[4*i+1]<<16)|(_blk[4*i+2]<<8)|_blk[4*i+3];
  for (let i=16;i<64;i++){
    const x=w[i-15], y=w[i-2];
    const s0=((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3);
    const s1=((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10);
    w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
  }
  let a=0x6a09e667|0,b=0xbb67ae85|0,c=0x3c6ef372|0,d=0xa54ff53a|0,
      e=0x510e527f|0,f=0x9b05688c|0,g=0x1f83d9ab|0,h=0x5be0cd19|0;
  for (let i=0;i<64;i++){
    const S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    const ch=(e&f)^(~e&g);
    const t1=(h+S1+ch+K[i]+w[i])|0;
    const S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    const maj=(a&b)^(a&c)^(b&c);
    const t2=(S0+maj)|0;
    h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
  }
  return (0x6a09e667 + a)|0;               // h0
}

/* ---- harness --------------------------------------------------------------- */
const buU8  = new Uint8Array(INLEN);       // input for JS impls (varied per call)
const buBuf = Buffer.alloc(INLEN);         // input for node crypto
for (let i=0;i<INLEN;i++){ buU8[i]=i*7+1; buBuf[i]=i*7+1; }

function fmt(n){ return n.toLocaleString('en-US'); }
function line(name, rate, note){
  const pass = rate >= TARGET ? 'PASS' : 'FAIL';
  const x = (rate/TARGET).toFixed(2);
  console.log(`  ${name.padEnd(34)} ${fmt(Math.round(rate)).padStart(15)} /s  ${pass} (${x}x target)`
              + (note ? `   ${note}` : ''));
}
function benchSync(fn, seconds=SECONDS){
  for (let i=0;i<20000;i++){ buU8[0]=i&0xff; buBuf[0]=i&0xff; fn(i); }   // warmup + JIT
  let n=0; const t0=process.hrtime.bigint();
  const end=t0+BigInt(Math.round(seconds*1e9));
  while (process.hrtime.bigint() < end){
    for (let i=0;i<20000;i++){ buU8[0]=n&0xff; buBuf[0]=n&0xff; fn(n); n++; }
  }
  const dt=Number(process.hrtime.bigint()-t0)/1e9;
  return n/dt;
}
async function benchAsync(makePromise, seconds, batch){
  await Promise.all(Array.from({length:Math.min(batch,1000)},(_,i)=>makePromise(i))); // warmup
  let n=0; const t0=process.hrtime.bigint();
  const end=t0+BigInt(Math.round(seconds*1e9));
  while (process.hrtime.bigint() < end){
    const ps=new Array(batch);
    for (let i=0;i<batch;i++){ buBuf[0]=n&0xff; ps[i]=makePromise(n); n++; }
    await Promise.all(ps);
  }
  const dt=Number(process.hrtime.bigint()-t0)/1e9;
  return n/dt;
}

(async () => {
  console.log(`\nSHA-256 throughput on ${INLEN}-byte input  (node ${process.version}, ${CORES} cores)`);
  console.log(`Target to keep the GPU fed: ${fmt(TARGET)}/s single-thread  (11,000 seeds/s x 256)\n`);

  // sanity: the specialized h0 must equal the top word of the reference digest
  const ref = compactSha256(buU8);
  const refH0 = ((ref[0]<<24)|(ref[1]<<16)|(ref[2]<<8)|ref[3])|0;
  if (sha256_1blk_h0(buU8) !== refH0){ console.error('!! sha256_1blk_h0 MISMATCH vs reference'); process.exit(1); }
  console.log('  (correctness: sha256_1blk_h0 == top word of compact sha256  ✓)\n');

  console.log('PURE JS');
  line('compact sha256 (current, in use)', benchSync((n)=>compactSha256(buU8)),
       'allocs K+m+w+out every call');
  line('sha256_1blk_h0 (no-alloc, 1 blk)', benchSync((n)=>sha256_1blk_h0(buU8)),
       'K hoisted, buffers reused');

  console.log('\nNODE BUILT-IN crypto (native OpenSSL)');
  line('crypto.createHash per call', benchSync((n)=>crypto.createHash('sha256').update(buBuf).digest()),
       'new Hash obj each call');
  if (typeof crypto.hash === 'function'){
    line('crypto.hash one-shot', benchSync((n)=>crypto.hash('sha256', buBuf, 'buffer')),
         'Node >=20.12/21.7');
  } else {
    console.log('  crypto.hash one-shot                 (unavailable on ' + process.version
                + ' — added in Node 20.12/21.7; ~fastest native for tiny inputs)');
  }

  console.log('\nWEB CRYPTO (crypto.subtle.digest — ASYNC, same API the browser exposes)');
  const subtle = crypto.webcrypto.subtle;
  line('subtle.digest, awaited serially', await benchAsync((n)=>subtle.digest('SHA-256', buBuf), SECONDS, 1),
       'one promise per hash');
  line('subtle.digest, batched x1000',    await benchAsync((n)=>subtle.digest('SHA-256', buBuf), SECONDS, 1000),
       'Promise.all(1000)');

  const best = benchSync((n)=>sha256_1blk_h0(buU8));
  console.log('\nSUMMARY');
  console.log(`  Best single-thread here: ~${fmt(Math.round(best))}/s (no-alloc JS).`);
  console.log(`  Target ${fmt(TARGET)}/s -> ` +
    (best>=TARGET ? 'met on ONE core.'
                  : `needs ~${Math.ceil(TARGET/best)} cores (Web Workers) OR the checksum on the GPU.`));
  console.log(`  Projected across ${CORES} cores: ~${fmt(Math.round(best*CORES))}/s.\n`);
})();
