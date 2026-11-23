/*
 * OpenQPEP Native C99 Centered Binomial Distribution (CBD_1 / CBD_2) Samplers,
 * Calyx Sovereign-Pentad Sovereign-Pentad Plain-LWE Matrix-Vector Accelerators, and ABI Probe.
 * Official Release 1.1.0 — Calyx Labs Inc. (CPOSLS-1.0)
 */
#include <stdint.h>
#include <stddef.h>

#define QLX_Q 3329
#define QVS_Q 8380417

/* Capability bitmask returned by openqpep_native_abi_info() */
#define ABI_PORTABLE_C99 0x01
#define ABI_AVX2         0x02
#define ABI_NEON         0x04

uint32_t openqpep_native_abi_info(void) {
    uint32_t flags = ABI_PORTABLE_C99;
#if defined(__AVX2__)
    flags |= ABI_AVX2;
#endif
#if defined(__ARM_NEON) || defined(__aarch64__)
    flags |= ABI_NEON;
#endif
    return flags;
}

static inline int32_t ct_caddq_cbd(int32_t a, int32_t q) {
    return a + ((a >> 31) & q);
}

void openqpep_cbd2_3329(const uint8_t *buf, int32_t *out) {
    if (!buf || !out) return;
    for (int i = 0; i < 128; i++) {
        uint8_t b = buf[i];
        int32_t a0 = (b & 1) + ((b >> 1) & 1);
        int32_t b0 = ((b >> 2) & 1) + ((b >> 3) & 1);
        int32_t a1 = ((b >> 4) & 1) + ((b >> 5) & 1);
        int32_t b1 = ((b >> 6) & 1) + ((b >> 7) & 1);
        int32_t d0 = a0 - b0;
        int32_t d1 = a1 - b1;
        out[2 * i] = ct_caddq_cbd(d0, QLX_Q);
        out[2 * i + 1] = ct_caddq_cbd(d1, QLX_Q);
    }
}

void openqpep_cbd1_3329(const uint8_t *buf, int32_t *out) {
    if (!buf || !out) return;
    for (int i = 0; i < 64; i++) {
        uint8_t b = buf[i];
        for (int j = 0; j < 4; j++) {
            int32_t a = (b >> (2 * j)) & 1;
            int32_t c = (b >> (2 * j + 1)) & 1;
            int32_t d = a - c;
            out[4 * i + j] = ct_caddq_cbd(d, QLX_Q);
        }
    }
}

void openqpep_cbd2_qvs(const uint8_t *buf, int32_t *out) {
    if (!buf || !out) return;
    for (int i = 0; i < 128; i++) {
        uint8_t b = buf[i];
        int32_t a0 = (b & 1) + ((b >> 1) & 1);
        int32_t b0 = ((b >> 2) & 1) + ((b >> 3) & 1);
        int32_t a1 = ((b >> 4) & 1) + ((b >> 5) & 1);
        int32_t b1 = ((b >> 6) & 1) + ((b >> 7) & 1);
        int32_t d0 = a0 - b0;
        int32_t d1 = a1 - b1;
        out[2 * i] = ct_caddq_cbd(d0, QVS_Q);
        out[2 * i + 1] = ct_caddq_cbd(d1, QVS_Q);
    }
}

/*
 * Calyx Sovereign-Pentad (CSP-Omega): Native C99 Unstructured Plain-LWE
 * row-accumulated matrix-vector multiply over Z_65536 (zero ring ideal / zero NTT).
 * Computes dst[j] = (dst[j] + scalar * row[j]) mod 65536 for j in [0, n).
 */
void openqpep_plain_lwe_row_accum_u16(
    uint16_t *dst,
    const uint16_t *row,
    uint16_t scalar,
    uint32_t n
) {
    if (!dst || !row) return;
    for (uint32_t j = 0; j < n; j++) {
        dst[j] = (uint16_t)(dst[j] + (uint16_t)(scalar * row[j]));
    }
}

/*
 * Computes dot_out[j] = (e_row[j] + sum_{k=0}^{n-1} a_row[k] * s_flat[k * nbar + j]) mod 65536
 * for j in [0, nbar).
 */
void openqpep_plain_lwe_keygen_row_u16(
    uint16_t *b_row,
    const uint16_t *e_row,
    const uint16_t *a_row,
    const uint16_t *s_flat,
    uint32_t n,
    uint32_t nbar
) {
    if (!b_row || !e_row || !a_row || !s_flat) return;
    for (uint32_t j = 0; j < nbar; j++) {
        uint16_t acc = e_row[j];
        for (uint32_t k = 0; k < n; k++) {
            size_t idx = (size_t)k * (size_t)nbar + (size_t)j;
            acc = (uint16_t)(acc + (uint16_t)(a_row[k] * s_flat[idx]));
        }
        b_row[j] = acc;
    }
}
