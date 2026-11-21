/* OpenQPEP v1.0.0-rc — Android NDK JNI Bridge (arm64-v8a NEON + x86_64 AVX2) */
#include <stdint.h>
#include <stddef.h>

extern void openqpep_ntt_3329(int16_t poly[256]);
extern void openqpep_inv_ntt_3329(int16_t poly[256]);
extern int openqpep_native_abi_info(void);

#ifdef __ANDROID__
#include <jni.h>
JNIEXPORT jint JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeAbiVersion(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return (jint)openqpep_native_abi_info();
}

JNIEXPORT void JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeNtt3329(JNIEnv *env, jclass cls, jshortArray coeffs) {
    (void)cls;
    if (!coeffs || (*env)->GetArrayLength(env, coeffs) != 256) return;
    jshort *ptr = (*env)->GetShortArrayElements(env, coeffs, NULL);
    if (!ptr) return;
    openqpep_ntt_3329((int16_t *)ptr);
    (*env)->ReleaseShortArrayElements(env, coeffs, ptr, 0);
}
#endif
