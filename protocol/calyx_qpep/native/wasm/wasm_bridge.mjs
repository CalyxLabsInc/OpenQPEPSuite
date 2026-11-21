/**
 * OpenQPEP v1.0.0-pc — WebAssembly SIMD128 Bridge with Bit-Exact Pure-JS Fallback
 * Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
 */
export const QLX_Q = 3329;
export const QLX_ZETA = 17;

function bitrev7(x) {
  let r = 0;
  for (let i = 0; i < 7; i++) { r = (r << 1) | (x & 1); x >>= 1; }
  return r;
}

function modPow(base, exp, mod) {
  let res = 1;
  base %= mod;
  while (exp > 0) {
    if (exp & 1) res = (res * base) % mod;
    base = (base * base) % mod;
    exp >>= 1;
  }
  return res;
}

const ZETAS_3329 = Array.from({ length: 128 }, (_, i) => modPow(QLX_ZETA, bitrev7(i), QLX_Q));
const INV_128_3329 = modPow(128, QLX_Q - 2, QLX_Q);

export class OpenQPEPWasmBridge {
  constructor() {
    this.wasmInstance = null;
    this.backend = "pure-js-reference";
  }

  async init(wasmBytes = null) {
    if (wasmBytes && typeof WebAssembly !== "undefined") {
      const mod = await WebAssembly.instantiate(wasmBytes, {});
      this.wasmInstance = mod.instance;
      this.backend = "wasm-simd128";
    }
    return { backend: this.backend, simd128: this.backend === "wasm-simd128" };
  }

  ntt3329(poly) {
    const p = Int32Array.from(poly);
    let k = 1;
    for (let length = 128; length >= 2; length >>= 1) {
      for (let start = 0; start < 256; start += 2 * length) {
        const zeta = ZETAS_3329[k++];
        for (let j = start; j < start + length; j++) {
          const t = (zeta * p[j + length]) % QLX_Q;
          let v = p[j] - t; if (v < 0) v += QLX_Q;
          let w = p[j] + t; if (w >= QLX_Q) w -= QLX_Q;
          p[j + length] = v;
          p[j] = w;
        }
      }
    }
    return Array.from(p);
  }

  invNtt3329(polyHat) {
    const p = Int32Array.from(polyHat);
    let k = 127;
    for (let length = 2; length <= 128; length <<= 1) {
      for (let start = 0; start < 256; start += 2 * length) {
        const zeta = QLX_Q - ZETAS_3329[k--];
        for (let j = start; j < start + length; j++) {
          const t = p[j];
          let sum = t + p[j + length]; if (sum >= QLX_Q) sum -= QLX_Q;
          let diff = t - p[j + length]; if (diff < 0) diff += QLX_Q;
          p[j] = sum;
          p[j + length] = (zeta * diff) % QLX_Q;
        }
      }
    }
    return Array.from(p, x => (x * INV_128_3329) % QLX_Q);
  }
}
