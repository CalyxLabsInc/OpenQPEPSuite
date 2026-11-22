# OpenQPEP Official Release 1.0.0 (v1.0.0) — Android NDK CMakeLists.txt (arm64-v8a NEON & x86_64 AVX2)
cmake_minimum_required(VERSION 3.22.1)
project(openqpep C)

add_library(openqpep SHARED
    ntt_3329.c
    ntt_8380417.c
    cbd.c
    pentad_accel.c
    openqpep_jni.c
)
target_compile_options(openqpep PRIVATE -O3 -std=c99 -fPIC -Wall -Wextra -Werror -ftree-vectorize)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_compile_options(openqpep PRIVATE -march=armv8-a+simd)
elseif(ANDROID_ABI STREQUAL "x86_64")
    target_compile_options(openqpep PRIVATE -mavx2)
endif()
