// crackworker.js -- one shard of a CPU crack, off the main thread.
// Each worker loads its OWN rxe wasm core (so it can unrank its slice of the
// keyspace) plus the shared BIP39 crypto, then sweeps [start,end): for words
// mode it enumerates candidate MNEMONICS x a fixed passphrase (optionally
// checksum-filtered); for passphrase mode a fixed mnemonic x candidate
// PASSPHRASES. On a hit it posts it and stops; the main thread terminate()s the
// pool. This is what makes words-mode multicore (the unrank sweep AND the
// PBKDF2 both parallelize) -- the GPU can't help there (varying HMAC key).
//
// Correctness note: the seed/derive/compare here is the SAME bip39crypto used
// (and gated 25/25) on the main thread -- workers are a scheduling change only.
'use strict';
// Propagate the ?v= cache-bust from the Worker URL to our importScripts, so a
// plain reload picks up edited modules here too (http.server sends no cache
// headers). The main thread spawns us as new Worker('crackworker.js?v=bN').
const _v = self.location.search || '';
importScripts('../wasm/rxecore.js'+_v, '../wasm/rxecore_api.js'+_v, 'bip39.js'+_v, 'bip39crypto.js'+_v);

let core = null, C = null, V = null;
async function ensureCore(wordlist){
  if (core) return;
  C = globalThis.BIP39Crypto;
  core = await globalThis.RxeCoreAPI.loadRxeCore({ moduleArgs:{ locateFile: p => '../wasm/'+p+_v } });
  core.registerDict('bip39-en', wordlist);
  ['bip39en','bip39','en','english'].forEach(a=>{ try{ core.registerDict(a, wordlist); }catch(e){} });
  V = globalThis.BIP39.makeValidator(wordlist);
}
function hexToBytes(h){ const o=new Uint8Array(h.length/2); for(let i=0;i<o.length;i++) o[i]=parseInt(h.substr(i*2,2),16); return o; }

onmessage = async (e) => {
  const d = e.data;
  if (!d) return;

  // DERIVE mode: parallel secp256k1 derive+compare on GPU-produced seeds (the
  // address crack's EC, moved off the main thread). No rxe core needed here.
  if (d.type === 'derive') {
    C = C || globalThis.BIP39Crypto;
    const seeds = new Uint8Array(d.seedsBuf);
    const taddr = { type:d.addrType, program:hexToBytes(d.programHex) };
    const plan = d.plan.filter(pp => C.purposeType(pp.purpose) === taddr.type);
    const changes = (d.changes && d.changes.length) ? d.changes : [0];
    const gap = Math.max(1, d.gap || 1);
    let hit = null;
    for (let i=0; i<d.n && !hit; i++) {
      const seed = seeds.subarray(i*64, i*64+64);
      for (const pp of plan) {
        const acct = C.deriveHardenedPath(seed, [pp.purpose, pp.coin||0, pp.account||0]);
        for (const ch of changes) { const chNode = C.ckdNormal(acct, ch);
          for (let idx=0; idx<gap; idx++) { const node = C.ckdNormal(chNode, idx);
            const tg = C.pubToTarget(C.privToPub(node.k), pp.purpose);
            if (tg.type===taddr.type && C.eq(tg.program, taddr.program)) { hit = { index:d.startIndex+i, path:{...pp, change:ch, index:idx} }; break; } }
          if (hit) break; }
        if (hit) break; }
    }
    postMessage(hit ? { type:'derivehit', id:d.id, batchId:d.batchId, index:hit.index, path:hit.path }
                    : { type:'derivedone', id:d.id, batchId:d.batchId });
    return;
  }

  if (d.type !== 'run') return;
  try {
    await ensureCore(d.wordlist);
    const set = core.parse(d.pattern);
    const isWords = d.mode === 'words';
    const isAddr  = d.target.kind === 'address';
    const tcc   = isAddr ? null : hexToBytes(d.target.chainCodeHex);
    const taddr = isAddr ? { type:d.target.addrType, program:hexToBytes(d.target.programHex) } : null;
    const plan  = isAddr ? d.plan.filter(pp => C.purposeType(pp.purpose) === taddr.type) : d.plan;
    const changes = (d.changes && d.changes.length) ? d.changes : [0];
    const gap = Math.max(1, d.gap || 1);
    const reqCsum = d.requireChecksum !== false;
    const pass = d.passphrase || '';
    // sweepOnly: this worker only unranks + checksum-filters and streams the
    // surviving mnemonics back; the MAIN thread GPU-seeds them. That parallelizes
    // the sweep (the real bottleneck for a multi-unknown-word checksum-on crack)
    // while the GPU does the KDF -- neither alone was enough.
    const sweepOnly = !!d.sweepOnly;
    let swept = 0, seeded = 0, lastPost = performance.now();
    let candBuf = [];
    const flushCand = (force) => { if (candBuf.length && (force || candBuf.length>=512)) { postMessage({ type:'cand', id:d.id, items:candBuf, swept }); candBuf=[]; } };
    // Report on a wall-clock cadence, not every N candidates -- in passphrase
    // mode (or checksum-off) a small shard may never reach a swept-count
    // threshold, so the UI would sit blank until 'done'.
    const maybePost = () => { const now = performance.now(); if (now - lastPost >= 250) { lastPost = now; if(sweepOnly) flushCand(true); postMessage({ type:'progress', id:d.id, swept, seeded }); } };

    // Candidate fetch backed by the batched sequential unrank (one seek + N
    // odometer-steps, ~5x the per-index unrank). Falls back to unrank on an
    // older core lacking the export.
    const UB = 4096; let _cbBase = -1, _cb = null, _useBatch = true;
    const candAt = (i) => {
      if (_useBatch) {
        if (!(_cb && i >= _cbBase && i < _cbBase + _cb.length)) {
          const r = set.unrankBatch ? set.unrankBatch(i, Math.min(UB, d.end - i)) : null;
          if (r === null) { _useBatch = false; return set.unrank(BigInt(i)); }
          _cbBase = i; _cb = r;
        }
        return _cb[i - _cbBase];
      }
      return set.unrank(BigInt(i));
    };

    for (let i = d.start; i < d.end; i++) {
      let mn, pw;
      if (isWords) {
        mn = candAt(i); pw = pass;
        if (reqCsum && !(mn !== null && V.isValid(mn))) { swept++; maybePost(); continue; }
      } else {
        pw = candAt(i); mn = d.mnemonic;
      }
      if (sweepOnly) { swept++; seeded++; candBuf.push({ mn, index:i }); flushCand(false); maybePost(); continue; }
      seeded++;
      const seed = C.mnemonicToSeed(mn, pw);
      let hit = null;
      if (isAddr) {
        for (const pp of plan) {
          const acct = C.deriveHardenedPath(seed, [pp.purpose, pp.coin||0, pp.account||0]);
          for (const ch of changes) {
            const chNode = C.ckdNormal(acct, ch);
            for (let idx = 0; idx < gap; idx++) {
              const node = C.ckdNormal(chNode, idx);
              const tg = C.pubToTarget(C.privToPub(node.k), pp.purpose);
              if (tg.type === taddr.type && C.eq(tg.program, taddr.program)) { hit = { ...pp, change:ch, index:idx }; break; }
            }
            if (hit) break;
          }
          if (hit) break;
        }
      } else {
        for (const pp of d.plan) {
          if (C.eq(C.accountNode(seed, pp.purpose, pp.account, pp.coin).c, tcc)) { hit = pp; break; }
        }
      }
      swept++;
      if (hit) { postMessage({ type:'hit', id:d.id, index:i, candidate:(isWords?mn:pw), path:hit, swept, seeded }); set.free(); return; }
      maybePost();
    }
    if (sweepOnly) flushCand(true);
    set.free();
    postMessage({ type:'done', id:d.id, swept, seeded });
  } catch (err) {
    postMessage({ type:'error', id:d.id, message: String(err && err.message || err) });
  }
};
