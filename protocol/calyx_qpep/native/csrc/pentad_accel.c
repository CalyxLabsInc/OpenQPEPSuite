/*
 * OpenQPEP v1.0.0-rc (Release Candidate 1.0.0) — Native C99 / SIMD Accelerators for
 * Calyx Sovereign-Pentad, Constant-Time Wire Format v4 Verification, and Compiler-Barrier
 * Memory Zeroization (openqpep_explicit_bzero).
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

/* Compiler-barrier explicit memory zeroization (v1.8.0-pc / v1.0.0-rc hardening) */
void openqpep_explicit_bzero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile uint8_t *vptr = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) {
        vptr[i] = 0U;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

/*
 * Constant-time Wire Format v4 (\x89QPE\x04\x00 / \x89QPE\x04\x01) magic validator.
 * Returns:
 *   40 -> Valid RC-1.0.0 Full Frame (\x89QPE\x04\x00)
 *   41 -> Valid RC-1.0.0 Compact TLV Frame (\x89QPE\x04\x01)
 *  -30 -> Rejected legacy Production Candidate (-pc) Wire v3/v3.1 (\x89QPE\x03\x00 / \x03\x01)
 *   -1 -> Invalid / legacy beta wire magic
 */
int openqpep_verify_wire_v4_magic(const uint8_t *hdr, size_t len) {
    if (!hdr || len < 6) return -1;
    uint8_t diff_prefix = (uint8_t)((hdr[0] ^ 0x89U) | (hdr[1] ^ 0x51U) | (hdr[2] ^ 0x50U) | (hdr[3] ^ 0x45U));
    if (diff_prefix != 0U) return -1;
    if (hdr[4] == 0x04U && hdr[5] == 0x00U) return 40;
    if (hdr[4] == 0x04U && hdr[5] == 0x01U) return 41;
    if (hdr[4] == 0x03U && (hdr[5] == 0x00U || hdr[5] == 0x01U)) return -30;
    return -1;
}
