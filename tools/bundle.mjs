// Builds dist/reseed39.html: the whole app in ONE file, so publishing (or
// carrying it onto an offline machine) is a single copy.
//
// What gets inlined: every app <script>, the librxe wasm (via the SINGLE_FILE
// build rxecore-single.js, wasm as base64), the BIP39 wordlist, and the WGSL
// shaders. The crack Web Worker can't reference a sibling file in a one-file
// build, so its source (deps + crackworker.js, minus importScripts) is inlined
// and handed to the page as a Blob URL: when the file is SERVED (http/https),
// multicore + the GPU derive pool stay alive; when opened from file:// a worker
// can't start and the code falls back to single-thread (so: serve it locally,
// even offline -- see DEPLOY.md).
//
// Prereq: wasm/rxecore-single.js exists (run wasm/build.sh; it builds it
// alongside rxecore.js). Run: node tools/bundle.mjs

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const R = (p) => readFile(root + p, 'utf8');
// Defensive: keep a stray "</script>" inside inlined code from closing the tag.
const safe = (s) => s.replace(/<\/script>/gi, '<\\/script>');

const [html, rxecore, api, bip39, model, wordset, crypto, electrum, gpucrack, i18n,
       crackworker, wordlist, wgslP, wgslPW, wgslS] = await Promise.all([
  R('estimator/index.html'),
  R('wasm/rxecore-single.js'), R('wasm/rxecore_api.js'),
  R('estimator/bip39.js'), R('estimator/model.js'), R('estimator/wordset.js'),
  R('estimator/bip39crypto.js'), R('estimator/electrum.js'), R('estimator/gpucrack.js'),
  R('estimator/i18n.js'), R('estimator/crackworker.js'),
  R('data/english.txt'),
  R('estimator/pbkdf2.wgsl'), R('estimator/pbkdf2_words.wgsl'), R('estimator/sha512.wgsl'),
].map((p) => p));

// The crack Worker: its deps concatenated with the served-mode importScripts
// line removed (everything is already present in the blob). Uses the SINGLE_FILE
// core so the worker carries its own wasm.
const workerSrc = [rxecore, api, bip39, crypto, electrum,
  crackworker.replace(/^\s*importScripts\([^;]*;\s*$/m, '// importScripts inlined below (single-file build)')
].join('\n;\n');
const workerB64 = Buffer.from(workerSrc, 'utf8').toString('base64');

// Globals the runtime shims read, injected BEFORE the app scripts.
const pre = `<script>
window.__ENGLISH_TXT = ${JSON.stringify(wordlist)};
window.__WGSL = {
  "pbkdf2.wgsl": ${JSON.stringify(wgslP)},
  "pbkdf2_words.wgsl": ${JSON.stringify(wgslPW)},
  "sha512.wgsl": ${JSON.stringify(wgslS)}
};
(function(){ try{
  var bin = atob(${JSON.stringify(workerB64)});
  var u8 = new Uint8Array(bin.length); for (var i=0;i<bin.length;i++) u8[i]=bin.charCodeAt(i);
  window.__CRACKWORKER_URL = URL.createObjectURL(new Blob([u8], {type:'application/javascript'}));
}catch(e){ /* file:// or no Blob worker -> single-thread fallback kicks in */ } })();
</script>`;

const scripts = [rxecore, api, bip39, model, wordset, crypto, electrum, gpucrack, i18n]
  .map((s) => `<script>\n${safe(s)}\n</script>`).join('\n');

// Swap the served <script src=...> block (rxecore.js .. i18n.js) for the inlined
// globals + scripts. indexOf/slice (not .replace) so the base64 payloads are
// copied verbatim -- a replacement string would treat $&/$' specially.
const startTag = '<script src="../wasm/rxecore.js?v=b60"></script>';
const endTag = '<script src="../estimator/i18n.js?v=b60"></script>';
const si = html.indexOf(startTag);
const ei = html.indexOf(endTag);
if (si < 0 || ei < 0) throw new Error('could not find the <script src> block to replace (did the ?v= stamp change?)');
const body = html.slice(0, si) + pre + '\n' + scripts + html.slice(ei + endTag.length);

await mkdir(root + 'dist', { recursive: true });
await writeFile(root + 'dist/reseed39.html', body);
const kb = Math.round(Buffer.byteLength(body) / 1024);
console.log(`bundle: dist/reseed39.html, ${kb} KB (one file; serve it — even offline — to keep multicore)`);
