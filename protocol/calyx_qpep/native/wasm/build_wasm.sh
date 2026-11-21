#!/usr/bin/env bash
# OpenQPEP v1.1.7-pc — Compile libopenqpep C99 kernels to standalone WebAssembly SIMD128
set -euo pipefail
emcc -O3 -msimd128 -std=c99 \
  -s STANDALONE_WASM=1 --no-entry \
  -s EXPORTED_FUNCTIONS='["_openqpep_ntt_3329","_openqpep_inv_ntt_3329","_openqpep_ntt_base_mul_3329","_openqpep_ntt_qvs","_openqpep_inv_ntt_qvs","_openqpep_cbd1_3329","_openqpep_cbd2_3329","_openqpep_plain_lwe_row_accum_u16","_openqpep_native_abi_info"]' \
  ../csrc/ntt_3329.c ../csrc/ntt_8380417.c ../csrc/cbd.c ../csrc/pentad_accel.c \
  -o openqpep_wasm.wasm
echo "[OK] Built openqpep_wasm.wasm (WASM SIMD128)"
