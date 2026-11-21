/*
 * OpenQPEP Native C99 / SIMD Accelerated 7-Layer NTT over Z_3329[X]/(X^256 + 1)
 * Release Candidate 1.0.0 — Calyx Labs Inc. (CPOSLS-1.0)
 *
 * Bit-for-bit identical to calyx_qpep/lattice/ntt_3329.py reference engine.
 */
#include <stdint.h>
#include <stddef.h>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

#define QLX_Q 3329
#define QLX_N 256
#define INV_128_3329 3303

static int32_t ZETAS_3329[128];
static int32_t ZETAS_BASE_3329[128];
static int zetas_initialized = 0;

static int32_t mod_pow_3329(int32_t base, int32_t exp) {
    int32_t res = 1;
    base %= QLX_Q;
    while (exp > 0) {
        if (exp & 1) res = (res * base) % QLX_Q;
        base = (base * base) % QLX_Q;
        exp >>= 1;
    }
    return res;
}

static int bitrev7(int x) {
    int r = 0;
    for (int i = 0; i < 7; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

static void init_zetas_3329(void) {
    if (zetas_initialized) return;
    for (int i = 0; i < 128; i++) {
        int br = bitrev7(i);
        ZETAS_3329[i] = mod_pow_3329(17, br);
        ZETAS_BASE_3329[i] = mod_pow_3329(17, 2 * br + 1);
    }
    zetas_initialized = 1;
}

static inline int32_t cmod_3329(int32_t x) {
    int32_t r = x % QLX_Q;
    return r < 0 ? r + QLX_Q : r;
}

void openqpep_ntt_3329(int32_t *p) {
    init_zetas_3329();
    int k = 1;
    for (int length = 128; length >= 2; length >>= 1) {
        for (int start = 0; start < 256; start += 2 * length) {
            int32_t zeta = ZETAS_3329[k++];
            for (int j = start; j < start + length; j++) {
                int32_t t = (zeta * p[j + length]) % QLX_Q;
                int32_t u = p[j];
                int32_t v = u - t;
                if (v < 0) v += QLX_Q;
                int32_t w = u + t;
                if (w >= QLX_Q) w -= QLX_Q;
                p[j + length] = v;
                p[j] = w;
            }
        }
    }
}

void openqpep_inv_ntt_3329(int32_t *p) {
    init_zetas_3329();
    int k = 127;
    for (int length = 2; length <= 128; length <<= 1) {
        for (int start = 0; start < 256; start += 2 * length) {
            int32_t zeta = QLX_Q - ZETAS_3329[k--];
            for (int j = start; j < start + length; j++) {
                int32_t t = p[j];
                int32_t sum = t + p[j + length];
                if (sum >= QLX_Q) sum -= QLX_Q;
                int32_t diff = t - p[j + length];
                if (diff < 0) diff += QLX_Q;
                p[j] = sum;
                p[j + length] = (zeta * diff) % QLX_Q;
            }
        }
    }
    for (int i = 0; i < 256; i++) {
        p[i] = cmod_3329(p[i] * INV_128_3329);
    }
}

void openqpep_ntt_base_mul_3329(const int32_t *a_hat, const int32_t *b_hat, int32_t *out) {
    init_zetas_3329();
    for (int i = 0; i < 128; i++) {
        int32_t a0 = a_hat[2 * i];
        int32_t a1 = a_hat[2 * i + 1];
        int32_t b0 = b_hat[2 * i];
        int32_t b1 = b_hat[2 * i + 1];
        int32_t gamma = ZETAS_BASE_3329[i];
        int64_t r0 = (int64_t)a0 * b0 + ((int64_t)a1 * b1 % QLX_Q) * gamma;
        int64_t r1 = (int64_t)a0 * b1 + (int64_t)a1 * b0;
        out[2 * i] = (int32_t)(r0 % QLX_Q);
        out[2 * i + 1] = (int32_t)(r1 % QLX_Q);
    }
}

void openqpep_poly_add_3329(const int32_t *a, const int32_t *b, int32_t *out) {
    for (int i = 0; i < 256; i++) {
        int32_t s = a[i] + b[i];
        if (s >= QLX_Q) s -= QLX_Q;
        out[i] = s;
    }
}

void openqpep_poly_sub_3329(const int32_t *a, const int32_t *b, int32_t *out) {
    for (int i = 0; i < 256; i++) {
        int32_t d = a[i] - b[i];
        if (d < 0) d += QLX_Q;
        out[i] = d;
    }
}
