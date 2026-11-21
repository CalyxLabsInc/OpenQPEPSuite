/*
 * OpenQPEP v1.1.0-pc — Native C99 / SIMD Accelerators for Tier 10 Calyx Sovereign-Pentad
 * (GF(256) polynomial multiplication & Binary Goppa XOR syndrome accumulation).
 * Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
 */
#include <stdint.h>
#include <stddef.h>

uint8_t openqpep_gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(-(b & 1));
        p ^= (uint8_t)(a & mask);
        uint8_t hi = (uint8_t)(a & 0x80);
        a <<= 1;
        a ^= (uint8_t)(hi ? 0x1B : 0x00);
        b >>= 1;
    }
    return p;
}

void openqpep_xor_accum_bytes(uint8_t *dst, const uint8_t *src, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}
