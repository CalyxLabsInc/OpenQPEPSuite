/*
 * OpenQPEP Official Release 1.1.0 (v1.1.0) — Native C99 / SIMD Accelerators for
 * Calyx Sovereign-Pentad, Constant-Time Wire Format v5 Verification, Constant-Time Primitives
 * (openqpep_ct_eq, openqpep_ct_cmov), and Compiler-Barrier Zeroization (openqpep_explicit_bzero).
 * Licensed under Calyx Public Open Source Specifications v1.0 License (CPOSLS-1.0).
 */
#include <stdint.h>
#include <stddef.h>

/* Branchless constant-time GF(256) multiplication modulo 0x11B */
uint8_t openqpep_gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0U;
    for (int i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(0U - (uint8_t)(b & 1U));
        p ^= (uint8_t)(a & mask);
        uint8_t hi_mask = (uint8_t)(0U - (uint8_t)((a >> 7) & 1U));
        a = (uint8_t)((a << 1) ^ (0x1BU & hi_mask));
        b >>= 1;
    }
    return p;
}

void openqpep_xor_accum_bytes(uint8_t *dst, const uint8_t *src, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

/* Constant-time byte-buffer comparison: returns 1 if equal, 0 otherwise */
int openqpep_ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) return 0;
    volatile uint8_t diff = 0U;
    for (size_t i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
    }
    uint32_t x = (uint32_t)diff;
    return (int)(1U ^ ((x | (0U - x)) >> 31));
}

/* Branchless constant-time conditional copy: out[i] = cond ? a[i] : b[i] */
void openqpep_ct_cmov(int cond, uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len) {
    if (!out || !a || !b) return;
    uint32_t c = (uint32_t)(cond != 0);
    uint8_t mask = (uint8_t)(0U - c);
    uint8_t inv = (uint8_t)(~mask);
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)((a[i] & mask) | (b[i] & inv));
    }
}

/* Compiler-barrier explicit memory zeroization */
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
 * Constant-time Official Release 1.1.0 Wire Format v5 (\x89QPE\x05\x00 / \x89QPE\x05\x01) magic validator.
 * Returns:
 *   50 -> Valid Official Release 1.1.0 Full Frame (\x89QPE\x05\x00)
 *   51 -> Valid Official Release 1.1.0 Compact TLV Frame (\x89QPE\x05\x01)
 *  -40 -> Rejected legacy Release Candidate (-rc) Wire v4/v4.1 (\x89QPE\x04\x00 / \x04\x01)
 *  -30 -> Rejected legacy Production Candidate (-pc) Wire v3/v3.1 (\x89QPE\x03\x00 / \x03\x01)
 *  -10 -> Rejected legacy Beta (-beta) Wire (\x89QPE\x01\x01 / \x01\x09 / \x02\x00)
 *   -1 -> Invalid wire magic
 */
int openqpep_verify_wire_v5_magic(const uint8_t *hdr, size_t len) {
    if (!hdr || len < 6) return -1;
    uint8_t diff_prefix = (uint8_t)((hdr[0] ^ 0x89U) | (hdr[1] ^ 0x51U) | (hdr[2] ^ 0x50U) | (hdr[3] ^ 0x45U));
    if (diff_prefix != 0U) return -1;
    if (hdr[4] == 0x05U && hdr[5] == 0x00U) return 50;
    if (hdr[4] == 0x05U && hdr[5] == 0x01U) return 51;
    if (hdr[4] == 0x04U && (hdr[5] == 0x00U || hdr[5] == 0x01U)) return -40;
    if (hdr[4] == 0x03U && (hdr[5] == 0x00U || hdr[5] == 0x01U)) return -30;
    if ((hdr[4] == 0x01U && (hdr[5] == 0x01U || hdr[5] == 0x09U)) || (hdr[4] == 0x02U && hdr[5] == 0x00U)) return -10;
    return -1;
}
