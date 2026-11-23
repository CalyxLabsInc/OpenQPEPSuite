/* OpenQPEP Official Release 1.1.0 (v1.1.0) — Android NDK JNI Bridge (arm64-v8a NEON + x86_64 AVX2) */
#include <stdint.h>
#include <stddef.h>

extern void openqpep_ntt_3329(int32_t *poly);
extern void openqpep_inv_ntt_3329(int32_t *poly);
extern uint32_t openqpep_native_abi_info(void);
extern int openqpep_verify_wire_v5_magic(const uint8_t *hdr, size_t len);

#ifdef __ANDROID__
#include <jni.h>
JNIEXPORT jint JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeAbiVersion(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return (jint)openqpep_native_abi_info();
}

JNIEXPORT void JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeNtt3329(JNIEnv *env, jclass cls, jintArray coeffs) {
    (void)cls;
    if (!coeffs || (*env)->GetArrayLength(env, coeffs) != 256) return;
    jint *ptr = (*env)->GetIntArrayElements(env, coeffs, NULL);
    if (!ptr) return;
    openqpep_ntt_3329((int32_t *)ptr);
    (*env)->ReleaseIntArrayElements(env, coeffs, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeInvNtt3329(JNIEnv *env, jclass cls, jintArray coeffs) {
    (void)cls;
    if (!coeffs || (*env)->GetArrayLength(env, coeffs) != 256) return;
    jint *ptr = (*env)->GetIntArrayElements(env, coeffs, NULL);
    if (!ptr) return;
    openqpep_inv_ntt_3329((int32_t *)ptr);
    (*env)->ReleaseIntArrayElements(env, coeffs, ptr, 0);
}

JNIEXPORT jint JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeVerifyWireV5Magic(JNIEnv *env, jclass cls, jbyteArray hdr) {
    (void)cls;
    if (!hdr) return -1;
    jsize n = (*env)->GetArrayLength(env, hdr);
    if (n < 6) return -1;
    jbyte *ptr = (*env)->GetByteArrayElements(env, hdr, NULL);
    if (!ptr) return -1;
    int rc = openqpep_verify_wire_v5_magic((const uint8_t *)ptr, (size_t)n);
    (*env)->ReleaseByteArrayElements(env, hdr, ptr, JNI_ABORT);
    return (jint)rc;
}
#endif
