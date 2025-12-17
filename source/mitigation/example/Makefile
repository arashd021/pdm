# =========================
# Compiler and common flags
# =========================

CC      := gcc
PDM_SRC := ../PDM-encrypt.c

COMMON_FLAGS := -g -fno-omit-frame-pointer -fno-stack-protector -pthread -DPDM_MASKING=1
ARCH_FLAGS   := -maes -msse2 -march=native
DEBUG_FLAGS  := -O0 -no-pie
OPT_FLAGS    := -O2

LIBS_OPENSSL := -lcrypto -lcapstone
LIBS_WOLFSSL := -lwolfssl -lcapstone

# =========================
# WolfSSL paths (must exist)
# =========================

CF_WOLFSSL_DIR ?= $(HOME)/wolfssl

WOLFSSL_INC := -I$(CF_WOLFSSL_DIR)/include
WOLFSSL_LIB := -L$(CF_WOLFSSL_DIR)/lib

# =========================
# Targets
# =========================

OPENSSL_BINS := openssl/ecdh openssl/ecdsa openssl/rsa
WOLFSSL_BINS := wolfssl/aes

ALL_BINS := $(OPENSSL_BINS) $(WOLFSSL_BINS)

.PHONY: all clean

all: $(ALL_BINS)

# =========================
# OpenSSL targets
# =========================

openssl/ecdh: openssl/ecdh.c $(PDM_SRC)
	$(CC) -o $@ $^ \
	$(COMMON_FLAGS) $(ARCH_FLAGS) $(DEBUG_FLAGS) \
	$(LIBS_OPENSSL)

openssl/ecdsa: openssl/ecdsa.c $(PDM_SRC)
	$(CC) -o $@ $^ \
	$(COMMON_FLAGS) $(ARCH_FLAGS) $(DEBUG_FLAGS) \
	$(LIBS_OPENSSL)

openssl/rsa: openssl/rsa.c $(PDM_SRC)
	$(CC) -o $@ $^ \
	$(COMMON_FLAGS) $(ARCH_FLAGS) $(DEBUG_FLAGS) \
	$(LIBS_OPENSSL)

# =========================
# WolfSSL targets
# =========================

wolfssl/aes: wolfssl/aes.c $(PDM_SRC)
	$(CC) -o $@ $^ \
	$(COMMON_FLAGS) $(OPT_FLAGS) \
	-fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args \
	-fPIE -pie \
	$(WOLFSSL_INC) $(WOLFSSL_LIB) \
	$(LIBS_WOLFSSL)

# =========================
# Cleanup
# =========================

clean:
	rm -f $(ALL_BINS)
