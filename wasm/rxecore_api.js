// rxecore_api.js -- ergonomic JS wrapper over the librxe->wasm core.
//
// This exposes librxe's EXACT enumeration primitives (cardinality, unrank,
// rank) to JavaScript. It contains NO counting or bijection logic of its own
// (THE DRIFT RULE) -- every number here comes from librxe via rxecore.wasm.
// Cardinalities and indices are JS BigInt (they routinely exceed 2^53).
//
// Usage:
//   const { loadRxeCore } = require('./rxecore_api.js');
//   const rxe = await loadRxeCore();
//   const set = rxe.parse('[a-z]{4}');
//   set.cardinality();      // 456976n
//   set.unrank(0n);         // 'aaaa'
//   set.free();

// Works in BOTH node (require) and the browser (rxecore.js loaded via <script>,
// which defines a global `RxeCore` factory). No node-only imports at top level.
const _path = (typeof require === 'function') ? require('path') : null;

let _factoryPromise = null;

async function loadRxeCore(opts = {}) {
  let factory;
  if (typeof globalThis !== 'undefined' && typeof globalThis.RxeCore !== 'undefined') {
    factory = globalThis.RxeCore;                     // browser: <script src=rxecore.js>
  } else if (typeof require === 'function') {
    factory = require(opts.modulePath || _path.join(__dirname, 'rxecore.js')); // node
  } else {
    throw new Error('rxecore.js not found (load it via <script> before this file)');
  }
  if (!_factoryPromise) _factoryPromise = factory(opts.moduleArgs || {});
  const Module = await _factoryPromise;
  return new RxeCoreApi(Module);
}

// librxe rxe_parse() flag bits (from rxe.h).
const FLAGS = {
  CASELESS: 0x0001,
  DOTALL: 0x0002,
  LEFT_TO_RIGHT: 0x0004,
};

class RxeCoreApi {
  constructor(Module) {
    this.M = Module;
    const c = (name, ret, args) => Module.cwrap(name, ret, args);
    this._parse = c('rxew_parse', 'number', ['string', 'number']);
    this._error = c('rxew_error', 'number', ['number']);
    this._errorMessage = c('rxew_error_message', 'string', ['number']);
    this._errorPos = c('rxew_error_pos', 'number', ['number']);
    this._isInfinite = c('rxew_is_infinite', 'number', ['number']);
    this._isShortlex = c('rxew_is_shortlex', 'number', ['number']);
    this._free = c('rxew_free', null, ['number']);
    this._freeStr = c('rxew_free_str', null, ['number']);
    this._cardinality = c('rxew_cardinality', 'number', ['number']); // char*
    this._unrank = c('rxew_unrank', 'number', ['number', 'string']); // char*
    this._rank = c('rxew_rank', 'number', ['number', 'string']);     // char*
    this._registerDict = c('rxew_register_dict', 'number', ['string', 'string']);
  }

  // Read a malloc'd C string returned by the wasm side, then free it.
  _takeString(ptr) {
    if (!ptr) return null;
    const s = this.M.UTF8ToString(ptr);
    this._freeStr(ptr);
    return s;
  }

  // Register a [:name:] dictionary from a newline-joined blob (or array).
  registerDict(name, words) {
    const blob = Array.isArray(words) ? words.join('\n') : String(words);
    const n = this._registerDict(name, blob);
    if (n < 0) throw new Error(`registerDict(${name}) failed`);
    return n;
  }

  // Parse a pattern; returns an RxeSet. Throws on a parse error with position.
  parse(pattern, flags = 0) {
    const h = this._parse(pattern, flags);
    if (!h) throw new Error('rxew_parse returned null (out of memory?)');
    const err = this._error(h);
    if (err !== 0) {
      const msg = this._errorMessage(h);
      const pos = this._errorPos(h);
      this._free(h);
      const e = new Error(`parse error: ${msg} (at offset ${pos})`);
      e.rxeStatus = err;
      e.rxeErrorPos = pos;
      throw e;
    }
    return new RxeSet(this, h);
  }
}

class RxeSet {
  constructor(api, handle) {
    this.api = api;
    this.h = handle;
    this._freed = false;
  }

  isInfinite() { return this.api._isInfinite(this.h) !== 0; }
  isShortlex() { return this.api._isShortlex(this.h) !== 0; }

  // Total cardinality as BigInt. Returns null for an infinite set (there is no
  // finite total; librxe's nitems then counts finite alternations only).
  cardinality() {
    if (this.isInfinite()) return null;
    const s = this.api._takeString(this.api._cardinality(this.h));
    return s === null ? null : BigInt(s);
  }

  // The i-th member (BigInt or integer index). Null if out of range / too big.
  unrank(index) {
    const dec = typeof index === 'bigint' ? index.toString() : String(index);
    return this.api._takeString(this.api._unrank(this.h, dec));
  }

  // Smallest index (BigInt) at which `s` sits, or null if not a member / the
  // set is one rank cannot handle.
  rank(s) {
    const r = this.api._takeString(this.api._rank(this.h, s));
    return r === null ? null : BigInt(r);
  }

  free() {
    if (!this._freed) { this.api._free(this.h); this._freed = true; }
  }
}

const _rxeApiExports = { loadRxeCore, FLAGS };
if (typeof module !== 'undefined' && module.exports) module.exports = _rxeApiExports;
if (typeof globalThis !== 'undefined') globalThis.RxeCoreAPI = _rxeApiExports; // window OR worker(self)
