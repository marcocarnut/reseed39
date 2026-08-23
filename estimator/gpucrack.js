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
  const code = await (await fetch('pbkdf2.wgsl')).text();
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

window.GpuCrack = { initGpu, gpuSeeds, benchmark, crackXpub, MAXSALT };
})();
