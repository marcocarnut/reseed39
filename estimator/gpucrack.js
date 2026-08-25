// gpucrack.js -- the in-browser xpub cracker (Batch 2). GPU computes BIP39 seeds
// with pbkdf2.wgsl (the 4096-compression bottleneck); the host does the cheap
// BIP32 hardened derive + chain-code compare (bip39crypto). secp256k1-free.
// Depends on window.BIP39Crypto. Browser-only (WebGPU).
'use strict';
(function(){
const STRIDE = 28;                 // u32/lane (112 bytes salt budget; salt+4<=111)
const MAXSALT = 107;               // "mnemonic"(8)+passphrase; salt+4<=111
let _gpu = null;

async function initGpu(){
  if (_gpu) return _gpu;
  if (!navigator.gpu) throw new Error('WebGPU not available');
  const adapter = await navigator.gpu.requestAdapter();
  if (!adapter) throw new Error('no WebGPU adapter');
  const dev = await adapter.requestDevice();
  const code = await (await fetch('pbkdf2.wgsl',{cache:'reload'})).text();
  const mod = dev.createShaderModule({ code });
  const info = await mod.getCompilationInfo();
  const errs = info.messages.filter(m=>m.type==='error');
  if (errs.length) throw new Error('pbkdf2.wgsl: '+errs[0].message);
  const pipe = dev.createComputePipeline({ layout:'auto', compute:{ module:mod, entryPoint:'main' } });
  const C = window.BIP39Crypto;
  const K = new Uint32Array(160); for (let i=0;i<80;i++){ K[i*2]=C.gpuK.hi[i]; K[i*2+1]=C.gpuK.lo[i]; }
  const ST=GPUBufferUsage.STORAGE, CD=GPUBufferUsage.COPY_DST;
  const kBuf = dev.createBuffer({size:K.byteLength, usage:ST|CD}); dev.queue.writeBuffer(kBuf,0,K);
  // A WebGPU device can be lost at any time -- a driver reset (a hot GPU tripping
  // the OS's timeout-detection-and-recovery), sleep/wake, or the browser dropping
  // the GPU process. When that happens the cached device is dead; clear it so the
  // next init re-acquires a fresh adapter+device (see _withGpuRetry).
  dev.lost.then((info)=>{ try{ console.warn('[gpucrack] WebGPU device lost:', info&&info.reason, info&&info.message); }catch(_){}
    if (_gpu && _gpu.dev===dev){ _gpu=null; _gpuW=null; } }).catch(()=>{});
  _gpu = { dev, pipe, kBuf, adapter };
  return _gpu;
}

// Does this error look like a lost/invalidated GPU device -- or a transient
// re-acquire failure right after a hard reset (requestAdapter() returns null for
// a moment while the driver recovers) -- vs a real bug or WebGPU being genuinely
// absent? "no WebGPU adapter" is retryable (the cooldown gives it time to come
// back); "WebGPU not available" (no navigator.gpu) is permanent and is NOT.
function _isDeviceLost(e){ const s=((e&&e.message)||String(e||'')).toLowerCase();
  if (s.includes('webgpu not available')) return false;      // permanent: no navigator.gpu
  return s.includes('device')&&s.includes('lost') || s.includes('external instance')
      || s.includes('destroyed') || s.includes('mapasync') || s.includes('adapter')
      || s.includes('invalid') && s.includes('device'); }
// Drop the cached device/pipelines so the next initGpu*/ re-acquires fresh ones.
function _resetGpu(){ try{ if(_gpu&&_gpu.dev&&_gpu.dev.destroy) _gpu.dev.destroy(); }catch(_){}
  _gpu=null; _gpuW=null; }
// Run a GPU op; if the device was lost, re-init and retry (with backoff) so a
// transient driver reset doesn't abort a multi-hour crack. Re-throws non-device
// errors (real bugs) immediately, and gives up after `tries` device re-inits.
let _gpuResets = 0;         // how many GPU ops we've recovered from a lost device this session
// Adaptive cooldown after a device loss. Start at the base (min); DOUBLE it on
// each consecutive failure up to a cap; RESET to the base only once the GPU has
// run clean past a stability window (so a flaky-under-heat GPU keeps backing off,
// but a one-off blip is forgiven). Times in ms.
let _coolBaseMs = 60000;          // minimum / starting cooldown (configurable via UI)
let _coolCapMs  = 30*60*1000;     // cap: 30 min
let _coolStabilityMs = 30*60*1000;// must run clean this long to reset to the base
let _coolCurMs  = _coolBaseMs;    // current (backed-off) cooldown
let _lastResumeAt = 0;            // when we last resumed after a recovery (0 = never)
let _gpuMaxResets = 20;           // give up the crack after this many recoveries
let _gpuStatusCb = null;          // optional UI hook: called during cooldown + on resume
let _gpuCancel = null;            // optional isCancelled hook: breaks a long cooldown promptly
// Reset the per-crack GPU recovery state (call at the start of each crack).
function _resetGpuStats(){ _gpuResets=0; _coolCurMs=_coolBaseMs; _lastResumeAt=0; }
async function _withGpuRetry(fn){
  for (;;){
    try { return await fn(); }
    catch(e){
      if (!_isDeviceLost(e)) throw e;                 // a real bug -- surface it now
      const msg=((e&&e.message)||String(e||'')).toLowerCase();
      // A null adapter on the VERY FIRST attempt (nothing recovered yet) means
      // there's genuinely no usable GPU -- fail fast instead of looping maxResets
      // times over escalating cooldowns on a GPU-less box.
      if (_gpuResets===0 && msg.includes('adapter'))
        throw new Error('no usable WebGPU device available');
      // Hard stop: allow up to _gpuMaxResets recoveries, then give up (an unstable
      // GPU shouldn't keep a crack "alive" forever). Checked before incrementing so
      // the counter reads exactly the number of recoveries that happened.
      if (_gpuResets >= _gpuMaxResets)
        throw new Error(`GPU gave up after ${_gpuResets} recoveries (max ${_gpuMaxResets}) -- it appears unstable. Let it cool and try again, or raise the limit.`);
      _gpuResets++;
      // Adaptive backoff: if the GPU ran clean past the stability window since the
      // last recovery, this is a fresh incident -> back to the base. Otherwise the
      // failures are clustering -> double (capped).
      const now = performance.now();
      if (_lastResumeAt > 0){
        if (now - _lastResumeAt > _coolStabilityMs) _coolCurMs = _coolBaseMs;
        else _coolCurMs = Math.min(_coolCurMs*2, _coolCapMs);
      }
      try{ console.warn(`[gpucrack] GPU op failed (${(e&&e.message)||e}); recovering -- restart #${_gpuResets}/${_gpuMaxResets}, cooldown ${Math.round(_coolCurMs/1000)}s`); }catch(_){}
      _resetGpu();
      // Cool-down: a device loss is often thermal; retrying in 300ms just trips it
      // again. Wait _coolCurMs, ticking a status callback each second so the UI can
      // show a countdown -- and checking the cancel hook so Stop breaks a long
      // cooldown promptly instead of hanging up to 30 min.
      const total = Math.max(0, _coolCurMs);
      for (let waited=0; waited<total; waited+=1000){
        let cancelled=false; if (_gpuCancel){ try{ cancelled=!!_gpuCancel(); }catch(_){} }
        if (cancelled){ if (_gpuStatusCb) try{ _gpuStatusCb({ cooling:false, cooldownMs:_coolCurMs, restart:_gpuResets, maxResets:_gpuMaxResets }); }catch(_){}
          throw new Error('cancelled during GPU cooldown'); }
        if (_gpuStatusCb) try{ _gpuStatusCb({ cooling:true, remainingMs: total-waited, cooldownMs:_coolCurMs, restart:_gpuResets, maxResets:_gpuMaxResets }); }catch(_){}
        await new Promise(r=>setTimeout(r, Math.min(1000, total-waited)));
      }
      _lastResumeAt = performance.now();   // resume time -> the "ran clean for how long?" clock
      if (_gpuStatusCb) try{ _gpuStatusCb({ cooling:false, cooldownMs:_coolCurMs, restart:_gpuResets, maxResets:_gpuMaxResets }); }catch(_){}
    }
  }
}

// Compute seeds (Uint8Array(count*64)) for `passphrases` under a FIXED mnemonic.
// Over-long passphrases (salt+4>111) fall back to the JS reference per-candidate.
async function gpuSeeds(g, mid, mnemonic, passphrases){
  const C = window.BIP39Crypto;
  const n = passphrases.length;
  const out = new Uint8Array(n*64);
  // partition: GPU-eligible vs JS-fallback
  const idxGpu = [], salts = [];
  for (let i=0;i<n;i++){
    const s = C.utf8('mnemonic'+C.nfkd(passphrases[i]));
    if (s.length <= MAXSALT) { idxGpu.push(i); salts.push(s); }
    else { const seed=C.mnemonicToSeed(mnemonic, passphrases[i]); out.set(seed, i*64); }
  }
  const m = idxGpu.length;
  if (m > 0) {
    // device-INDEPENDENT host arrays
    const sl = new Uint32Array(m), sd = new Uint32Array(m*STRIDE);
    for (let k=0;k<m;k++){ const s=salts[k]; sl[k]=s.length; for (let j=0;j<s.length;j++) sd[k*STRIDE+(j>>2)] |= (s[j]<<((3-(j&3))*8)); }
    // device-DEPENDENT: re-acquire device + kBuf on retry (ignore the passed-in
    // `g`, whose device may have been lost mid-crack).
    await _withGpuRetry(async ()=>{
      const { dev, pipe, kBuf } = await initGpu();
      const ST=GPUBufferUsage.STORAGE,U=GPUBufferUsage.UNIFORM,CS=GPUBufferUsage.COPY_SRC,CD=GPUBufferUsage.COPY_DST;
      const mk=(a,us)=>{const b=dev.createBuffer({size:Math.max(16,a.byteLength),usage:us});dev.queue.writeBuffer(b,0,a);return b;};
      const iB=mk(mid.ipad,ST|CD), oB=mk(mid.opad,ST|CD), lB=mk(sl,ST|CD), dB=mk(sd,ST|CD);
      const pB=mk(new Uint32Array([m,STRIDE,2048,0]),U|CD);
      const oBuf=dev.createBuffer({size:m*64,usage:ST|CS});
      const bg=dev.createBindGroup({layout:pipe.getBindGroupLayout(0),entries:[
        {binding:0,resource:{buffer:kBuf}},{binding:1,resource:{buffer:iB}},{binding:2,resource:{buffer:oB}},
        {binding:3,resource:{buffer:lB}},{binding:4,resource:{buffer:dB}},{binding:5,resource:{buffer:oBuf}},{binding:6,resource:{buffer:pB}}]});
      const enc=dev.createCommandEncoder(); const p=enc.beginComputePass(); p.setPipeline(pipe); p.setBindGroup(0,bg); p.dispatchWorkgroups(Math.ceil(m/64)); p.end();
      const stg=dev.createBuffer({size:m*64,usage:CD|GPUBufferUsage.MAP_READ}); enc.copyBufferToBuffer(oBuf,0,stg,0,m*64);
      dev.queue.submit([enc.finish()]); await stg.mapAsync(GPUMapMode.READ);
      const words=new Uint32Array(stg.getMappedRange().slice(0)); stg.unmap();
      for (let k=0;k<m;k++){ const o=idxGpu[k]*64; for (let w=0;w<16;w++){ const v=words[k*16+w]>>>0; out[o+w*4]=(v>>>24)&255; out[o+w*4+1]=(v>>>16)&255; out[o+w*4+2]=(v>>>8)&255; out[o+w*4+3]=v&255; } }
      [iB,oB,lB,dB,pB,oBuf,stg].forEach(b=>b.destroy&&b.destroy());
    });
  }
  return out;
}

// A short identifier for the current WebGPU adapter (for the benchmark cache).
async function getGpuInfo(){
  if (!navigator.gpu) return null;
  try {
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) return null;
    let info = adapter.info;
    if (!info && adapter.requestAdapterInfo) info = await adapter.requestAdapterInfo();
    if (!info) return 'WebGPU';
    const parts = [info.vendor, info.architecture, info.device, info.description].filter(Boolean);
    return parts.length ? parts.join(' ').trim().slice(0,80) : 'WebGPU';
  } catch(e){ return 'WebGPU'; }
}

// Measure raw GPU seed throughput (seeds/s).
async function benchmark(n){
  n = n||8192;
  const g = await initGpu();
  const C = window.BIP39Crypto;
  const mn='legal winner thank year wave sausage worth useful legal winner thank yellow';
  const mid = C.hmacMidstates(C.utf8(C.nfkd(mn)));
  const passes=[]; for (let i=0;i<n;i++) passes.push('bench'+i);
  await gpuSeeds(g, mid, mn, passes.slice(0,64));       // warm
  const t0=performance.now();
  await gpuSeeds(g, mid, mn, passes);
  const dt=(performance.now()-t0)/1000;
  return Math.round(n/dt);
}

// Crack an xpub passphrase. opts: { mnemonic, targetChainCode(Uint8Array 32),
// plan:[{purpose,account,coin}], total(Number), unrank(i)->string, batchSize,
// onProgress(done,total,rate), isCancelled()->bool }.
async function crackXpub(opts){
  const g = await initGpu();
  const C = window.BIP39Crypto;
  const mid = C.hmacMidstates(C.utf8(C.nfkd(opts.mnemonic)));
  const plan = opts.plan && opts.plan.length ? opts.plan : [{purpose:84,account:0,coin:0}];
  const total = opts.total, B = opts.batchSize||4096;
  const t0 = performance.now(); let done=0;
  for (let start=0; start<total; start+=B){
    if (opts.isCancelled && opts.isCancelled()) return { stopped:true, done };
    const n = Math.min(B, total-start);
    const _cb = opts.unrankBatch ? opts.unrankBatch(start, n) : null; const passes = new Array(n); for (let i=0;i<n;i++) passes[i]=_cb?_cb[i]:opts.unrank(start+i);
    const seeds = await gpuSeeds(g, mid, opts.mnemonic, passes);
    for (let i=0;i<n;i++){
      const seed = seeds.subarray(i*64,i*64+64);
      for (const pp of plan){
        const cc = C.accountNode(seed, pp.purpose, pp.account||0, pp.coin||0).c;
        if (C.eq(cc, opts.targetChainCode)) return { found: passes[i], path: pp, index: start+i, done: done+i+1 };
      }
    }
    done += n;
    if (opts.onProgress) opts.onProgress(done, total, done/((performance.now()-t0)/1000));
    await new Promise(r=>setTimeout(r,0));   // yield to the UI
  }
  return { found:null, done };
}

/* ===================== WORDS-mode GPU seeding ========================== *
 * The mnemonic varies per lane (it's the HMAC key), so pbkdf2_words.wgsl builds
 * each lane's ipad/opad midstates on the GPU from the mnemonic bytes, then runs
 * PBKDF2 against the FIXED salt ("mnemonic"+passphrase). Host just packs bytes.  */
const WSTRIDE = 64;          // u32/lane for the mnemonic (256 bytes; 24 words <= 215)
const WMAXMN  = 239;         // max mnemonic bytes (2-block key pre-hash fits)
let _gpuW = null;
async function initGpuWords(){
  if (_gpuW) return _gpuW;
  const { dev, adapter } = await initGpu();          // reuse device
  const code = await (await fetch('pbkdf2_words.wgsl',{cache:'reload'})).text();
  const mod = dev.createShaderModule({ code });
  const info = await mod.getCompilationInfo();
  const errs = info.messages.filter(m=>m.type==='error');
  if (errs.length) throw new Error('pbkdf2_words.wgsl: '+errs[0].message);
  const pipe = dev.createComputePipeline({ layout:'auto', compute:{ module:mod, entryPoint:'main' } });
  _gpuW = { dev, pipe };
  return _gpuW;
}
// Seeds (Uint8Array(n*64)) for candidate `mnemonics` under a FIXED passphrase.
// Over-long mnemonic/salt fall back to the JS reference per candidate.
let _wordsK = null;   // device-independent SHA-512 K schedule (built once)
function _getWordsK(C){ return _wordsK || (_wordsK=(()=>{ const K=new Uint32Array(160); for(let i=0;i<80;i++){K[i*2]=C.gpuK.hi[i];K[i*2+1]=C.gpuK.lo[i];} return K; })()); }
async function gpuSeedsWords(mnemonics, passphrase){
  const C = window.BIP39Crypto;
  const salt = C.utf8('mnemonic' + C.nfkd(passphrase||''));
  const n = mnemonics.length;
  const out = new Uint8Array(n*64);
  const idxGpu=[], mnBytes=[];
  for (let i=0;i<n;i++){
    const b = C.utf8(C.nfkd(mnemonics[i]));
    if (b.length<=WMAXMN && salt.length<=107) { idxGpu.push(i); mnBytes.push(b); }
    else out.set(C.mnemonicToSeed(mnemonics[i], passphrase||''), i*64);   // fallback
  }
  const m = idxGpu.length;
  if (m>0){
    // device-INDEPENDENT host arrays (safe to reuse across a device re-init)
    const K = _getWordsK(C);
    const sl = new Uint32Array(Math.ceil((salt.length+1)/4)+1); for(let j=0;j<salt.length;j++) sl[j>>2]|=(salt[j]<<((3-(j&3))*8));
    const md = new Uint32Array(m*WSTRIDE), ml = new Uint32Array(m);
    for (let k=0;k<m;k++){ const b=mnBytes[k]; ml[k]=b.length; for(let j=0;j<b.length;j++) md[k*WSTRIDE+(j>>2)]|=(b[j]<<((3-(j&3))*8)); }
    // device-DEPENDENT block: re-acquire the device + rebuild buffers on retry.
    await _withGpuRetry(async ()=>{
      const { dev, pipe } = await initGpuWords();
      const ST=GPUBufferUsage.STORAGE,U=GPUBufferUsage.UNIFORM,CS=GPUBufferUsage.COPY_SRC,CD=GPUBufferUsage.COPY_DST;
      const mk=(a,us)=>{const bf=dev.createBuffer({size:Math.max(16,a.byteLength),usage:us});dev.queue.writeBuffer(bf,0,a);return bf;};
      const kBuf=mk(K,ST|CD), sBuf=mk(sl,ST|CD), lBuf=mk(ml,ST|CD), dBuf=mk(md,ST|CD);
      const pBuf=mk(new Uint32Array([m,WSTRIDE,2048,salt.length]),U|CD);
      const oBuf=dev.createBuffer({size:m*64,usage:ST|CS});
      const bg=dev.createBindGroup({layout:pipe.getBindGroupLayout(0),entries:[
        {binding:0,resource:{buffer:kBuf}},{binding:1,resource:{buffer:sBuf}},{binding:2,resource:{buffer:lBuf}},
        {binding:3,resource:{buffer:dBuf}},{binding:4,resource:{buffer:oBuf}},{binding:5,resource:{buffer:pBuf}}]});
      const enc=dev.createCommandEncoder(); const p=enc.beginComputePass(); p.setPipeline(pipe); p.setBindGroup(0,bg); p.dispatchWorkgroups(Math.ceil(m/64)); p.end();
      const stg=dev.createBuffer({size:m*64,usage:CD|GPUBufferUsage.MAP_READ}); enc.copyBufferToBuffer(oBuf,0,stg,0,m*64);
      dev.queue.submit([enc.finish()]); await stg.mapAsync(GPUMapMode.READ);
      const words=new Uint32Array(stg.getMappedRange().slice(0)); stg.unmap();
      for (let k=0;k<m;k++){ const o=idxGpu[k]*64; for(let w=0;w<16;w++){ const v=words[k*16+w]>>>0; out[o+w*4]=(v>>>24)&255;out[o+w*4+1]=(v>>>16)&255;out[o+w*4+2]=(v>>>8)&255;out[o+w*4+3]=v&255; } }
      [kBuf,sBuf,lBuf,dBuf,pBuf,oBuf,stg].forEach(b=>b.destroy&&b.destroy());
    });
  }
  return out;
}

// Crack WORDS mode on the GPU: pipelined host sweep (unrank + optional checksum
// filter) feeding batched GPU seeding, then host derive + compare. opts:
// { passphrase, requireChecksum, validator, plan, tcc|taddr, changes, gap,
//   total, unrank, batchSize, onProgress, isCancelled }.
async function crackWordsGpu(opts){
  const C = window.BIP39Crypto;
  await initGpuWords();
  const isAddr = !!opts.taddr;
  const plan = isAddr ? opts.plan.filter(pp=>C.purposeType(pp.purpose)===opts.taddr.type) : opts.plan;
  const changes=(opts.changes&&opts.changes.length)?opts.changes:[0]; const gap=Math.max(1,opts.gap||1);
  const reqCsum = opts.requireChecksum!==false;
  const total=opts.total, B=opts.batchSize||8192;
  // Address is EC-bound: if workers are available, run the secp256k1 derive+compare
  // in PARALLEL across a pool (the paced host sweep + GPU seed stay on this thread).
  if (isAddr){
    const nW = Math.max(1, Math.min(opts.nWorkers||1, (self.navigator&&navigator.hardwareConcurrency)||8, 32));
    if (typeof Worker!=='undefined' && nW>1 && opts.workerUrl){
      const r = await _crackWordsAddrParallel(opts, plan, changes, gap, nW);
      if (!r || !r.__fallback) return r;   // fall through to inline on worker-spawn failure
    }
  }
  const t0=performance.now(); let done=0, seeded=0;
  // Sweep + checksum-filter [start,start+B) on the host into {n,mns,gidx}.
  const sweepFilter=(start)=>{
    const n=Math.min(B, total-start);
    const cands = opts.unrankBatch ? opts.unrankBatch(start, n) : null;
    const mns=[], gidx=[];
    for (let i=0;i<n;i++){ const mn=cands?cands[i]:opts.unrank(start+i); if(mn==null) continue; if(reqCsum && !opts.validator.isValid(mn)) continue; mns.push(mn); gidx.push(start+i); }
    return { n, mns, gidx };
  };
  const seed=(b)=> b.mns.length ? gpuSeedsWords(b.mns, opts.passphrase) : Promise.resolve(new Uint8Array(0));
  // DOUBLE-BUFFER: sweep+filter the NEXT batch on the host while the GPU seeds
  // the current one (and derive the current while the GPU seeds the next), so
  // the GPU stays fed instead of idling through the host sweep.
  let cur = sweepFilter(0), curSeedP = seed(cur), start = B;
  while (cur && !(opts.isCancelled && opts.isCancelled())){
    const next = start<total ? sweepFilter(start) : null;   // overlaps the GPU seed of `cur`
    start += B;
    const seeds = await curSeedP;
    const nextSeedP = next ? seed(next) : null;             // kick off next GPU seed before deriving
    for (let k=0;k<cur.mns.length;k++){
      const s=seeds.subarray(k*64,k*64+64);
      if (isAddr){
        for (const pp of plan){ const acct=C.deriveHardenedPath(s,[pp.purpose,pp.coin||0,pp.account||0]);
          for (const ch of changes){ const chNode=C.ckdNormal(acct,ch);
            for (let idx=0;idx<gap;idx++){ const node=C.ckdNormal(chNode,idx);
              const tg=C.pubToTarget(C.privToPub(node.k),pp.purpose);
              if(tg.type===opts.taddr.type&&C.eq(tg.program,opts.taddr.program)) return {found:cur.mns[k],path:{...pp,change:ch,index:idx},index:cur.gidx[k],done:done+k+1}; } } }
      } else {
        for (const pp of opts.plan){ if(C.eq(C.accountNode(s,pp.purpose,pp.account,pp.coin).c,opts.tcc)) return {found:cur.mns[k],path:pp,index:cur.gidx[k],done:done+k+1}; }
      }
      if((k&4095)===4095) await Promise.resolve();   // cheap microtask yield (no 4ms clamp)
    }
    seeded += cur.mns.length; done += cur.n;
    if (opts.onProgress){ const el=(performance.now()-t0)/1000; opts.onProgress(done,total,done/el,{seeded,seedRate:seeded/el}); }
    cur = next; curSeedP = nextSeedP;
  }
  return cur ? { stopped:true, done } : { found:null, done };
}

// WORDS+ADDRESS parallel: candidate MNEMONICS are seeded on the GPU (per-lane
// key), then the EC derive+compare runs across a worker pool. The host sweep is
// PACED (one batch per producer iteration + backpressure), so unlike the hybrid
// worker-sweep it can't flood memory when the checksum filter is off. Returns
// {__fallback:true} if the pool can't be spawned (caller then goes inline).
async function _crackWordsAddrParallel(opts, plan, changes, gap, nW){
  const C = window.BIP39Crypto;
  await initGpuWords();
  // Decouple the GPU SEED batch from the per-worker DERIVE task: seed a big batch
  // (the GPU is most efficient in bulk -- a 2k batch left it seed-bound), then
  // split those seeds into small tasks so every worker stays fed (a 16k task
  // would pin one worker for ~16s while the rest idle).
  const total=opts.total, SB=opts.addrSeedBatch||16384, TS=opts.addrTask||2048;
  const reqCsum = opts.requireChecksum!==false;
  const programHex=C.toHex(opts.taddr.program), addrType=opts.taddr.type;
  const sweepFilter=(start)=>{ const n=Math.min(SB,total-start);
    const cands=opts.unrankBatch?opts.unrankBatch(start,n):null; const mns=[],gidx=[];
    for(let i=0;i<n;i++){ const mn=cands?cands[i]:opts.unrank(start+i); if(mn==null)continue; if(reqCsum&&!opts.validator.isValid(mn))continue; mns.push(mn); gidx.push(start+i); }
    return {n,mns,gidx}; };
  return new Promise((resolve)=>{
    const workers=[], idle=[], pending=new Map(); const queue=[];
    let finished=false, batchId=0, dispatched=0, completed=0, sweepDone=false, seeded=0, done=0, poll=0, spawnFail=false;
    const t0=performance.now();
    const cleanup=()=>{ clearInterval(poll); workers.forEach(w=>{try{w.terminate()}catch(e){}}); };
    const finish=(r)=>{ if(finished)return; finished=true; cleanup(); resolve(r); };
    const report=()=>{ if(opts.onProgress){ const el=(performance.now()-t0)/1000||1e-6; opts.onProgress(Math.min(done,total),total,done/el,{seeded,seedRate:seeded/el}); } };
    const drain=()=>{ while(idle.length && queue.length && !finished){ const w=idle.shift(), task=queue.shift();
      pending.set(task.batchId, task);
      w.postMessage({ type:'derive', batchId:task.batchId, seedsBuf:task.seedsBuf, n:task.mns.length, startIndex:0,
        plan, addrType, programHex, changes, gap }, [task.seedsBuf]); } };
    for(let i=0;i<nW;i++){ let w; try{ w=new Worker(opts.workerUrl); }catch(e){ spawnFail=true; break; }
      workers.push(w); idle.push(w);
      w.onmessage=(e)=>{ const m=e.data; if(finished)return;
        if(m.type==='derivehit'){ const info=pending.get(m.batchId); finish({found:info.mns[m.index], path:m.path, index:info.gidx[m.index], done}); }
        else if(m.type==='derivedone'){ const info=pending.get(m.batchId); pending.delete(m.batchId); completed++; if(info) done+=info.n; idle.push(w); report(); drain();
          if(sweepDone && completed>=dispatched && !finished) finish({found:null, done}); } };
      w.onerror=(ev)=>finish({error:(ev&&ev.message)||'derive worker error'});
    }
    if(spawnFail || !workers.length){ cleanup(); return resolve({__fallback:true}); }
    poll=setInterval(()=>{ if(opts.isCancelled&&opts.isCancelled()) finish({stopped:true,done}); },200);
    (async ()=>{
      try{
        for(let start=0; start<total && !finished; start+=SB){
          const b=sweepFilter(start);
          if(!b.mns.length){ done+=b.n; report(); continue; }
          const seeds=await gpuSeedsWords(b.mns, opts.passphrase);   // one bulk GPU seed
          if(finished)return;
          seeded+=b.mns.length;
          // split the seeded batch into per-worker derive tasks (own transferable buffer)
          for(let o=0;o<b.mns.length;o+=TS){ const m=Math.min(TS,b.mns.length-o);
            const buf=seeds.slice(o*64,(o+m)*64);
            queue.push({ batchId:batchId++, seedsBuf:buf.buffer, mns:b.mns.slice(o,o+m), gidx:b.gidx.slice(o,o+m), n:m });
            dispatched++; drain(); }
          done += (b.n - b.mns.length);   // filtered-out candidates are swept immediately
          report();
          await new Promise(r=>setTimeout(r,0));
          // backpressure: cap seeded-but-underived tasks so we don't run ahead of the pool.
          while(queue.length>nW*4 && !finished) await new Promise(r=>setTimeout(r,4));
        }
        sweepDone=true;
        if(completed>=dispatched && !finished) finish({found:null, done});
      }catch(e){ finish({error:e.message}); }
    })();
  });
}

// Crack an ADDRESS passphrase. Unlike the xpub path this needs elliptic curve:
// the GPU still computes the seed (the bottleneck), but the host derives to
// m/purpose'/coin'/account'/change/index, takes the PUBKEY, builds the script
// program, and compares to the decoded target. opts: { mnemonic,
// target:{type,program}, plan:[{purpose,account,coin}], changes:[0|1...],
// gap, total, unrank, batchSize, onProgress, isCancelled }.
// A/B: batch the address host-derive EC (one Montgomery inverse per stage per
// batch, via privToPubBatch) vs per-candidate. Toggle GpuCrack.batchEC=false to
// compare. Only the simple plan (1 purpose, change [0], gap 1) is batched; other
// shapes fall through to per-candidate.
let BATCH_EC = true;
// Returns {i, tg} of the first batch match, or null. Batches the 3 privToPub
// stages (acct, change-node, index-node) across the n seeds.
function _addrBatchMatch(seeds, n, pp, target){
  const C = window.BIP39Crypto;
  const accts = new Array(n);
  for (let i=0;i<n;i++) accts[i]=C.deriveHardenedPath(seeds.subarray(i*64,i*64+64),[pp.purpose,pp.coin||0,pp.account||0]);
  const pubA = C.privToPubBatch(accts.map(a=>a.k));
  const chs = new Array(n); for (let i=0;i<n;i++) chs[i]=C.ckdNormalPub(accts[i], pubA[i], 0);
  const pubC = C.privToPubBatch(chs.map(c=>c.k));
  const nodes = new Array(n); for (let i=0;i<n;i++) nodes[i]=C.ckdNormalPub(chs[i], pubC[i], 0);
  const pubN = C.privToPubBatch(nodes.map(nd=>nd.k));
  for (let i=0;i<n;i++){
    const tg = C.pubToTarget(pubN[i], pp.purpose);
    if (tg.type===target.type && C.eq(tg.program, target.program)) return { i };
  }
  return null;
}

// Address crack: GPU seeds on the main thread, then the secp256k1 derive+compare
// (the EC-bound half) runs in PARALLEL across a worker pool -- the seeds are
// transferred to idle workers while the GPU seeds the next batch. Falls back to
// the single-thread inline path when workers/URL aren't available.
async function crackAddress(opts){
  const nW = Math.max(1, Math.min(opts.nWorkers||1, (self.navigator&&navigator.hardwareConcurrency)||8, 32));
  if (typeof Worker==='undefined' || nW<=1 || !opts.workerUrl) return _crackAddressInline(opts);
  return _crackAddressParallel(opts, nW);
}

async function _crackAddressParallel(opts, nW){
  const g = await initGpu();
  const C = window.BIP39Crypto;
  const mid = C.hmacMidstates(C.utf8(C.nfkd(opts.mnemonic)));
  const plan = (opts.plan||[]).filter(pp => C.purposeType(pp.purpose) === opts.target.type);
  if (!plan.length) return { found:null, done:0, mismatch:opts.target.type };
  const changes = (opts.changes && opts.changes.length) ? opts.changes : [0];
  const gap = Math.max(1, opts.gap||1);
  const total = opts.total, B = opts.batchSize||4096;
  const programHex = C.toHex(opts.target.program), addrType = opts.target.type;
  return new Promise((resolve)=>{
    const workers=[], idle=[], pending=new Map(); const queue=[];
    let finished=false, batchId=0, dispatched=0, completed=0, sweepDone=false, seeded=0, poll=0;
    const t0=performance.now();
    const cleanup=()=>{ clearInterval(poll); workers.forEach(w=>{try{w.terminate()}catch(e){}}); };
    const finish=(r)=>{ if(finished) return; finished=true; cleanup(); resolve(r); };
    const report=()=>{ if(opts.onProgress){ const el=(performance.now()-t0)/1000||1e-6; opts.onProgress(Math.min(seeded,total), total, seeded/el, {seeded, seedRate:seeded/el}); } };
    const drain=()=>{ while(idle.length && queue.length && !finished){ const w=idle.shift(), task=queue.shift();
      pending.set(task.batchId, task);
      w.__batch=task.batchId;
      w.postMessage({ type:'derive', batchId:task.batchId, seedsBuf:task.seedsBuf, n:task.n, startIndex:task.start,
        plan, addrType, programHex, changes, gap }, [task.seedsBuf]); } };
    for (let i=0;i<nW;i++){
      let w; try{ w=new Worker(opts.workerUrl); }catch(e){ cleanup(); return resolve(_crackAddressInline(opts)); }
      workers.push(w); idle.push(w);
      w.onmessage=(e)=>{ const m=e.data; if(finished) return;
        if(m.type==='derivehit'){ const info=pending.get(m.batchId); finish({ found:info.passes[m.index-info.start], path:m.path, index:m.index }); }
        else if(m.type==='derivedone'){ pending.delete(m.batchId); completed++; idle.push(w); drain();
          if(sweepDone && completed>=dispatched && !finished) finish({ found:null }); }
      };
    }
    poll=setInterval(()=>{ if(opts.isCancelled && opts.isCancelled()) finish({ stopped:true }); }, 200);
    (async ()=>{
      try{
        for (let start=0; start<total && !finished; start+=B){
          const n=Math.min(B, total-start);
          const cands = opts.unrankBatch ? opts.unrankBatch(start, n) : null;
          const passes = new Array(n); for (let i=0;i<n;i++) passes[i]=cands?cands[i]:opts.unrank(start+i);
          const seeds = await gpuSeeds(g, mid, opts.mnemonic, passes);
          if (finished) return;
          // gpuSeeds returns a fresh Uint8Array(n*64) each call, so transfer its
          // buffer directly (zero-copy) -- main doesn't need the seeds after this.
          queue.push({ batchId:batchId++, seedsBuf:seeds.buffer, n, start, passes });
          dispatched++; seeded+=n; report(); drain();
          await new Promise(r=>setTimeout(r,0));
          // backpressure: EC (workers) is the bottleneck, so cap the seed queue.
          while (queue.length > nW*3 && !finished) await new Promise(r=>setTimeout(r,4));
        }
        sweepDone=true;
        if (completed>=dispatched && !finished) finish({ found:null });
      }catch(e){ finish({ error:e.message }); }
    })();
  });
}

async function _crackAddressInline(opts){
  const g = await initGpu();
  const C = window.BIP39Crypto;
  const mid = C.hmacMidstates(C.utf8(C.nfkd(opts.mnemonic)));
  // Only derivations whose script type matches the target address are worth testing.
  const plan = (opts.plan||[]).filter(pp => C.purposeType(pp.purpose) === opts.target.type);
  if (!plan.length) return { found:null, done:0, mismatch:opts.target.type };
  const changes = (opts.changes && opts.changes.length) ? opts.changes : [0];
  const gap = Math.max(1, opts.gap||1);
  const simple = BATCH_EC && plan.length===1 && changes.length===1 && changes[0]===0 && gap===1;
  const total = opts.total, B = opts.batchSize||2048;
  const t0 = performance.now(); let done=0;
  for (let start=0; start<total; start+=B){
    if (opts.isCancelled && opts.isCancelled()) return { stopped:true, done };
    const n = Math.min(B, total-start);
    const _cb = opts.unrankBatch ? opts.unrankBatch(start, n) : null; const passes = new Array(n); for (let i=0;i<n;i++) passes[i]=_cb?_cb[i]:opts.unrank(start+i);
    const seeds = await gpuSeeds(g, mid, opts.mnemonic, passes);
    if (simple){
      const hit = _addrBatchMatch(seeds, n, plan[0], opts.target);
      if (hit) return { found: passes[hit.i], path:{...plan[0], change:0, index:0}, index:start+hit.i, done:done+hit.i+1 };
    } else {
      for (let i=0;i<n;i++){
        const seed = seeds.subarray(i*64,i*64+64);
        for (const pp of plan){
          const acct = C.deriveHardenedPath(seed, [pp.purpose, pp.coin||0, pp.account||0]);
          for (const ch of changes){
            const chNode = C.ckdNormal(acct, ch);
            for (let idx=0; idx<gap; idx++){
              const node = C.ckdNormal(chNode, idx);
              const tg = C.pubToTarget(C.privToPub(node.k), pp.purpose);
              if (tg.type===opts.target.type && C.eq(tg.program, opts.target.program))
                return { found: passes[i], path:{...pp, change:ch, index:idx}, index:start+i, done:done+i+1 };
            }
          }
        }
      }
    }
    done += n;
    if (opts.onProgress) opts.onProgress(done, total, done/((performance.now()-t0)/1000));
    await new Promise(r=>setTimeout(r,0));
  }
  return { found:null, done };
}

// Gate helper: GPU words-seeds vs the JS reference for a set of mnemonics.
async function gateWords(mnemonics, passphrase){
  const C = window.BIP39Crypto;
  const g = await gpuSeedsWords(mnemonics, passphrase||'');
  const out=[];
  for (let i=0;i<mnemonics.length;i++){
    const want=C.toHex(C.mnemonicToSeed(mnemonics[i], passphrase||''));
    const got=C.toHex(g.subarray(i*64,i*64+64));
    out.push({ mn:mnemonics[i], len:C.utf8(C.nfkd(mnemonics[i])).length, ok:got===want });
  }
  return out;
}

window.GpuCrack = { initGpu, gpuSeeds, benchmark, crackXpub, crackAddress, MAXSALT,
  initGpuWords, gpuSeedsWords, crackWordsGpu, gateWords, getGpuInfo,
  setBatchEC:(b)=>{ BATCH_EC=!!b; }, getBatchEC:()=>BATCH_EC,
  getGpuResets:()=>_gpuResets, resetGpuStats:_resetGpuStats,
  // base = minimum/starting cooldown; it doubles per consecutive failure up to
  // the cap, and resets to base after running clean past the stability window.
  setGpuCooldown:(ms)=>{ _coolBaseMs=Math.max(0, ms|0); _coolCurMs=_coolBaseMs; }, getGpuCooldown:()=>_coolBaseMs,
  getGpuCooldownCurrent:()=>_coolCurMs,
  setGpuCooldownCap:(ms)=>{ _coolCapMs=Math.max(0, ms|0); }, getGpuCooldownCap:()=>_coolCapMs,
  setGpuCooldownStability:(ms)=>{ _coolStabilityMs=Math.max(0, ms|0); }, getGpuCooldownStability:()=>_coolStabilityMs,
  setGpuMaxResets:(n)=>{ _gpuMaxResets=Math.max(1, n|0); }, getGpuMaxResets:()=>_gpuMaxResets,
  onGpuStatus:(fn)=>{ _gpuStatusCb = (typeof fn==='function') ? fn : null; },
  setCancelCheck:(fn)=>{ _gpuCancel = (typeof fn==='function') ? fn : null; } };
})();
