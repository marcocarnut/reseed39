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
  _gpu = { dev, pipe, kBuf, adapter };
  return _gpu;
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
    const { dev, pipe, kBuf } = g;
    const sl = new Uint32Array(m), sd = new Uint32Array(m*STRIDE);
    for (let k=0;k<m;k++){ const s=salts[k]; sl[k]=s.length; for (let j=0;j<s.length;j++) sd[k*STRIDE+(j>>2)] |= (s[j]<<((3-(j&3))*8)); }
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
    const passes = new Array(n); for (let i=0;i<n;i++) passes[i]=opts.unrank(start+i);
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
async function gpuSeedsWords(mnemonics, passphrase){
  const C = window.BIP39Crypto;
  const g = await initGpuWords();
  const { dev, pipe } = g;
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
    const K = g._K || (g._K = (()=>{ const K=new Uint32Array(160); for(let i=0;i<80;i++){K[i*2]=C.gpuK.hi[i];K[i*2+1]=C.gpuK.lo[i];} return K; })());
    const sl = new Uint32Array(Math.ceil((salt.length+1)/4)+1); for(let j=0;j<salt.length;j++) sl[j>>2]|=(salt[j]<<((3-(j&3))*8));
    const md = new Uint32Array(m*WSTRIDE), ml = new Uint32Array(m);
    for (let k=0;k<m;k++){ const b=mnBytes[k]; ml[k]=b.length; for(let j=0;j<b.length;j++) md[k*WSTRIDE+(j>>2)]|=(b[j]<<((3-(j&3))*8)); }
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
  const t0=performance.now(); let done=0, seeded=0;
  for (let start=0; start<total; start+=B){
    if (opts.isCancelled && opts.isCancelled()) return { stopped:true, done };
    const n=Math.min(B, total-start);
    // sweep + filter this batch on the host
    const mns=[], gidx=[];
    for (let i=0;i<n;i++){ const mn=opts.unrank(start+i); if(mn==null) continue; if(reqCsum && !opts.validator.isValid(mn)) continue; mns.push(mn); gidx.push(start+i); }
    if (mns.length){
      const seeds = await gpuSeedsWords(mns, opts.passphrase);
      seeded += mns.length;
      for (let k=0;k<mns.length;k++){
        const seed=seeds.subarray(k*64,k*64+64);
        if (isAddr){
          for (const pp of plan){ const acct=C.deriveHardenedPath(seed,[pp.purpose,pp.coin||0,pp.account||0]);
            for (const ch of changes){ const chNode=C.ckdNormal(acct,ch);
              for (let idx=0;idx<gap;idx++){ const node=C.ckdNormal(chNode,idx);
                const tg=C.pubToTarget(C.privToPub(node.k),pp.purpose);
                if(tg.type===opts.taddr.type&&C.eq(tg.program,opts.taddr.program)) return {found:mns[k],path:{...pp,change:ch,index:idx},index:gidx[k],done:done+k+1}; } } }
        } else {
          for (const pp of opts.plan){ if(C.eq(C.accountNode(seed,pp.purpose,pp.account,pp.coin).c,opts.tcc)) return {found:mns[k],path:pp,index:gidx[k],done:done+k+1}; }
        }
      }
    }
    done += n;
    if (opts.onProgress){ const el=(performance.now()-t0)/1000; opts.onProgress(done,total,done/el,{seeded,seedRate:seeded/el}); }
    await new Promise(r=>setTimeout(r,0));
  }
  return { found:null, done };
}

// Crack an ADDRESS passphrase. Unlike the xpub path this needs elliptic curve:
// the GPU still computes the seed (the bottleneck), but the host derives to
// m/purpose'/coin'/account'/change/index, takes the PUBKEY, builds the script
// program, and compares to the decoded target. opts: { mnemonic,
// target:{type,program}, plan:[{purpose,account,coin}], changes:[0|1...],
// gap, total, unrank, batchSize, onProgress, isCancelled }.
async function crackAddress(opts){
  const g = await initGpu();
  const C = window.BIP39Crypto;
  const mid = C.hmacMidstates(C.utf8(C.nfkd(opts.mnemonic)));
  // Only derivations whose script type matches the target address are worth testing.
  const plan = (opts.plan||[]).filter(pp => C.purposeType(pp.purpose) === opts.target.type);
  if (!plan.length) return { found:null, done:0, mismatch:opts.target.type };
  const changes = (opts.changes && opts.changes.length) ? opts.changes : [0];
  const gap = Math.max(1, opts.gap||1);
  const total = opts.total, B = opts.batchSize||2048;
  const t0 = performance.now(); let done=0;
  for (let start=0; start<total; start+=B){
    if (opts.isCancelled && opts.isCancelled()) return { stopped:true, done };
    const n = Math.min(B, total-start);
    const passes = new Array(n); for (let i=0;i<n;i++) passes[i]=opts.unrank(start+i);
    const seeds = await gpuSeeds(g, mid, opts.mnemonic, passes);
    for (let i=0;i<n;i++){
      const seed = seeds.subarray(i*64,i*64+64);
      for (const pp of plan){
        const acct = C.deriveHardenedPath(seed, [pp.purpose, pp.coin||0, pp.account||0]);
        for (const ch of changes){
          const chNode = C.ckdNormal(acct, ch);          // one derive per (candidate,purpose,change)
          for (let idx=0; idx<gap; idx++){
            const node = C.ckdNormal(chNode, idx);
            const tg = C.pubToTarget(C.privToPub(node.k), pp.purpose);
            if (tg.type===opts.target.type && C.eq(tg.program, opts.target.program))
              return { found: passes[i], path:{...pp, change:ch, index:idx}, index:start+i, done:done+i+1 };
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
  initGpuWords, gpuSeedsWords, crackWordsGpu, gateWords, getGpuInfo };
})();
