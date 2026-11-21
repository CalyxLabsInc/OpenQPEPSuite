# OpenQPEP Release Candidate 1.0.0 (v1.0.0-rc)
CC ?= cc
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
CFLAGS := -O3 -std=c99 -fPIC -Wall -Wextra

ifeq ($(PORTABLE),1)
  SIMD_FLAGS :=
else ifeq ($(UNAME_M),x86_64)
  SIMD_FLAGS := -mavx2 -ftree-vectorize
else ifeq ($(UNAME_M),aarch64)
  SIMD_FLAGS := -march=armv8-a -ftree-vectorize
else ifeq ($(UNAME_M),arm64)
  SIMD_FLAGS := -march=armv8-a -ftree-vectorize
else
  SIMD_FLAGS :=
endif

ifeq ($(UNAME_S),Darwin)
  LIBEXT := dylib
  LDFLAGS := -dynamiclib
else
  LIBEXT := so
  LDFLAGS := -shared
endif

TARGET := ../libopenqpep.$(LIBEXT)
SRCS := ntt_3329.c ntt_8380417.c cbd.c pentad_accel.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SIMD_FLAGS) $(LDFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f ../libopenqpep.so ../libopenqpep.dylib ../libopenqpep.dll

.PHONY: all clean
