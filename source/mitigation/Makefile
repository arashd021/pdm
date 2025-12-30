# =========================
# Compiler and common flags
# =========================

CC := gcc

# Now Makefile is in: source/mitigation/
# Sources are in:      source/mitigation/example/...
PDM_SO     := PDM-encrypt.so
PDM_SO_SRC := PDM-encrypt.c

COMMON_FLAGS := -g -fno-omit-frame-pointer -fno-stack-protector -pthread
ARCH_FLAGS   := -maes -msse2 -march=native
DEBUG_FLAGS  := -O0 -no-pie
OPT_FLAGS    := -O2
EXPORT_FLAGS := -rdynamic

# Build the handler as shared object
PDM_SO_FLAGS := -shared -fPIC -g -O0 -fno-omit-frame-pointer -fno-stack-protector -pthread -ldl -DPDM_MASKING=1
PDM_SO_LIBS  := -lcapstone

# Victim libs (capstone is NOT needed unless victim code uses it)
LIBS_OPENSSL := -lcrypto -pthread
LIBS_WOLFSSL := -lwolfssl -pthread

# =========================
# WolfSSL paths (must exist)
# =========================

CF_WOLFSSL_DIR ?= $(HOME)/wolfssl
WOLFSSL_INC := -I$(CF_WOLFSSL_DIR)/include
WOLFSSL_LIB := -L$(CF_WOLFSSL_DIR)/lib

# =========================
# Targets
# =========================

OPENSSL_BINS := example/openssl/ecdh example/openssl/ecdsa example/openssl/rsa
WOLFSSL_BINS := example/wolfssl/aes

ALL_BINS := $(OPENSSL_BINS) $(WOLFSSL_BINS)

.PHONY: all clean run-ecdh run-ecdsa run-rsa run-aes

all: $(PDM_SO) $(ALL_BINS)

# =========================
# PDM shared object target
# =========================

$(PDM_SO): $(PDM_SO_SRC)
	$(CC) -o $@ $^ $(PDM_SO_FLAGS) $(PDM_SO_LIBS)

# =========================
# OpenSSL targets (victims)
# =========================

example/openssl/ecdh: example/openssl/ecdh.c
	$(CC) -o $@ $^ \
	$(COMMON_FLAGS) $(ARCH_FLAGS) $(DEBUG_FLAGS) $(EXPORT_FLAGS) \
	$(LIBS_OPENSSL)

example/openssl/ecdsa: example/openssl/ecdsa.c
	$(CC) -o $@ $^ \
	$(COMMON_FLAGS) $(ARCH_FLAGS) $(DEBUG_FLAGS) $(EXPORT_FLAGS) \
	$(LIBS_OPENSSL)

example/openssl/rsa: example/openssl/rsa.c
	$(CC) -o $@ $^ \
	$(COMMON_FLAGS) $(ARCH_FLAGS) $(DEBUG_FLAGS) $(EXPORT_FLAGS) \
	$(LIBS_OPENSSL)

# =========================
# WolfSSL targets (victims)
# =========================

example/wolfssl/aes: example/wolfssl/aes.c
	$(CC) -o $@ $^ \
	$(OPT_FLAGS) $(EXPORT_FLAGS) \
	-fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args \
	-fPIE -pie \
	$(WOLFSSL_INC) $(WOLFSSL_LIB) \
	$(LIBS_WOLFSSL)

# =========================
# Convenience run targets
# =========================
# Note: When you run from mitigation/, LD_PRELOAD path is just ./PDM-encrypt.so

run-ecdh: $(PDM_SO) example/openssl/ecdh
	LD_PRELOAD=./$(PDM_SO) ./example/openssl/ecdh 2

run-ecdsa: $(PDM_SO) example/openssl/ecdsa
	LD_PRELOAD=./$(PDM_SO) ./example/openssl/ecdsa 2

run-rsa: $(PDM_SO) example/openssl/rsa
	LD_PRELOAD=./$(PDM_SO) ./example/openssl/rsa 2

run-aes: $(PDM_SO) example/wolfssl/aes
	LD_PRELOAD=./$(PDM_SO) ./example/wolfssl/aes

# =========================
# Cleanup
# =========================

clean:
	rm -f $(ALL_BINS) $(PDM_SO)
