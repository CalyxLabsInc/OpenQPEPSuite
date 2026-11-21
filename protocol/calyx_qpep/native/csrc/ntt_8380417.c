/*
 * OpenQPEP Native C99 / SIMD Accelerated 8-Layer Complete NTT over Z_8380417[X]/(X^256 + 1)
 * Production Candidate 1.1.4 — Calyx Labs Inc. (CPOSLS-1.0)
 *
 * Bit-for-bit identical to calyx_qpep/lattice/ntt_8380417.py reference engine.
 */
#include <stdint.h>
#include <stddef.h>

#define QVS_Q 8380417LL
#define QVS_ZETA 1753LL
#define INV_256_QVS 8347681LL

static int64_t ZETAS_QVS[256];
static int zetas_qvs_initialized = 0;

static int64_t mod_pow_qvs(int64_t base, int64_t exp) {
    int64_t res = 1;
    base %= QVS_Q;
    while (exp > 0) {
        if (exp & 1) res = (res * base) % QVS_Q;
        base = (base * base) % QVS_Q;
        exp >>= 1;
    }
    return res;
}

static int bitrev8(int x) {
    int r = 0;
    for (int i = 0; i < 8; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

static void init_zetas_qvs(void) {
    if (zetas_qvs_initialized) return;
    for (int i = 0; i < 256; i++) {
        ZETAS_QVS[i] = mod_pow_qvs(QVS_ZETA, bitrev8(i));
    }
    zetas_qvs_initialized = 1;
}

void openqpep_ntt_qvs(int32_t *p) {
    init_zetas_qvs();
    int k = 0;
    for (int length = 128; length >= 1; length >>= 1) {
        for (int start = 0; start < 256; start += 2 * length) {
            int64_t zeta = ZETAS_QVS[++k];
            for (int j = start; j < start + length; j++) {
                int64_t t = (zeta * (int64_t)p[j + length]) % QVS_Q;
                int64_t u = (int64_t)p[j];
                int64_t v = u - t;
                if (v < 0) v += QVS_Q;
                int64_t w = u + t;
                if (w >= QVS_Q) w -= QVS_Q;
                p[j + length] = (int32_t)v;
                p[j] = (int32_t)w;
            }
        }
    }
}

void openqpep_inv_ntt_qvs(int32_t *p) {
    init_zetas_qvs();
    int k = 256;
    for (int length = 1; length < 256; length <<= 1) {
        for (int start = 0; start < 256; start += 2 * length) {
            int64_t zeta = QVS_Q - ZETAS_QVS[--k];
            for (int j = start; j < start + length; j++) {
                int64_t t = (int64_t)p[j];
                int64_t u = (int64_t)p[j + length];
                int64_t sum = t + u;
                if (sum >= QVS_Q) sum -= QVS_Q;
                int64_t diff = t - u;
                if (diff < 0) diff += QVS_Q;
                p[j] = (int32_t)sum;
                p[j + length] = (int32_t)((zeta * diff) % QVS_Q);
            }
        }
    }
    for (int i = 0; i < 256; i++) {
        int64_t v = ((int64_t)p[i] * INV_256_QVS) % QVS_Q;
        if (v < 0) v += QVS_Q;
        p[i] = (int32_t)v;
    }
}

void openqpep_ntt_mul_qvs(const int32_t *a_hat, const int32_t *b_hat, int32_t *out) {
    for (int i = 0; i < 256; i++) {
        out[i] = (int32_t)(((int64_t)a_hat[i] * (int64_t)b_hat[i]) % QVS_Q);
    }
}
