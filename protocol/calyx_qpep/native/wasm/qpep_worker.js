/* OpenQPEP Official Release 1.1.0 (v1.1.0) — Off-Main-Thread Crypto Web Worker (WASM SIMD128 + Zero-Block UI) */
let wasmInstance = null;

async function initWasm(wasmBytes) {
  if (!wasmBytes) return false;
  try {
    const { instance } = await WebAssembly.instantiate(wasmBytes);
    wasmInstance = instance;
    return true;
  } catch (err) {
    return false;
  }
}

self.onmessage = async function (ev) {
  const { id, op, payload } = ev.data || {};
  try {
    if (op === 'init_wasm') {
      const ok = await initWasm(payload && payload.wasmBytes);
      self.postMessage({ id, ok, abi: wasmInstance ? wasmInstance.exports.openqpep_abi_version() : 0, version: '1.1.0' });
      return;
    }
    if (op === 'barrett_3329') {
      const x = Number(payload && payload.x) | 0;
      const out = wasmInstance ? wasmInstance.exports.openqpep_barrett_3329(x) : (((x % 3329) + 3329) % 3329);
      self.postMessage({ id, ok: true, result: out });
      return;
    }
    if (op === 'verify_wire_v5') {
      const hdr = payload && payload.hdr;
      const valid = Array.isArray(hdr) && hdr.length >= 6 && hdr[0] === 0x89 && hdr[1] === 0x51 && hdr[2] === 0x50 && hdr[3] === 0x45 && hdr[4] === 0x05 && (hdr[5] === 0x00 || hdr[5] === 0x01);
      self.postMessage({ id, ok: valid, wire_version: valid ? 'v5-official-1.1.0' : 'rejected' });
      return;
    }
    if (op === 'ping') {
      self.postMessage({ id, ok: true, worker: 'OpenQPEP-v1.1.0-WebWorker' });
      return;
    }
    self.postMessage({ id, ok: false, error: 'Unsupported worker op: ' + op });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err) });
  }
};
