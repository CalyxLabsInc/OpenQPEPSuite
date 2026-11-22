#!/usr/bin/env bash
# OpenQPEP Official Release 1.0.0 (v1.0.0) — Compile OpenQPEP Core to standalone WebAssembly SIMD128
set -euo pipefail
if command -v cargo >/dev/null 2>&1; then
  RUSTFLAGS="-C target-feature=+simd128" cargo build --manifest-path ../../../rust/openqpep-core/Cargo.toml --target wasm32-unknown-unknown --release
  cp ../../../rust/openqpep-core/target/wasm32-unknown-unknown/release/openqpep_core.wasm ./openqpep_wasm.wasm
  echo "[OK] Built openqpep_wasm.wasm via Rust wasm32-unknown-unknown (+simd128)"
elif command -v emcc >/dev/null 2>&1; then
  emcc -O3 -msimd128 -std=c99 -s STANDALONE_WASM=1 --no-entry \
    -s EXPORTED_FUNCTIONS='["_openqpep_ntt_3329","_openqpep_inv_ntt_3329","_openqpep_ntt_base_mul_3329","_openqpep_ntt_qvs","_openqpep_inv_ntt_qvs","_openqpep_cbd1_3329","_openqpep_cbd2_3329","_openqpep_plain_lwe_row_accum_u16","_openqpep_native_abi_info"]' \
    ../csrc/ntt_3329.c ../csrc/ntt_8380417.c ../csrc/cbd.c ../csrc/pentad_accel.c \
    -o openqpep_wasm.wasm
  echo "[OK] Built openqpep_wasm.wasm via Emscripten SIMD128"
else
  echo "[INFO] Neither cargo nor emcc installed; using prebuilt standalone openqpep_wasm.wasm"
fi
