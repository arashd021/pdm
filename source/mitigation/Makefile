CC := gcc

PDM_SO := PDM-encrypt.so
OPENSSL_BINS := example/openssl/ecdh example/openssl/ecdsa example/openssl/rsa
WOLFSSL_BINS := example/wolfssl/aes example/wolfssl/eddsa
ALL_BINS := $(OPENSSL_BINS) $(WOLFSSL_BINS)

CF_WOLFSSL_DIR ?= $(HOME)/wolfssl

DEBUG ?= 0
ifeq ($(DEBUG),1)
  DBG_DEFINE := -DDEBUG
else
  DBG_DEFINE :=
endif

.PHONY: all clean run-ecdh run-ecdsa run-rsa run-aes run-eddsa

all: $(PDM_SO) $(ALL_BINS)

$(PDM_SO): PDM-encrypt.c
	$(CC) -shared -fPIC -g -O0 -DPDM_MASKING=1 $(DBG_DEFINE) -o $@ $^ -lcapstone -lcrypto -ldl

example/openssl/ecdh: example/openssl/ecdh.c
	$(CC) -g -O0 -no-pie -rdynamic -o $@ $^ -lcrypto

example/openssl/ecdsa: example/openssl/ecdsa.c
	$(CC) -g -O0 -no-pie -rdynamic -o $@ $^ -lcrypto

example/openssl/rsa: example/openssl/rsa.c
	$(CC) -g -O0 -no-pie -rdynamic -o $@ $^ -lcrypto

example/wolfssl/aes: example/wolfssl/aes.c
	$(CC) -O2 -fPIE -pie -rdynamic -o $@ $^ -I$(CF_WOLFSSL_DIR)/include -L$(CF_WOLFSSL_DIR)/lib -lwolfssl

example/wolfssl/eddsa: example/wolfssl/eddsa.c
	$(CC) -O2 -fPIE -pie -rdynamic -o $@ $^ -I$(CF_WOLFSSL_DIR)/include -L$(CF_WOLFSSL_DIR)/lib -lwolfssl

run-ecdh: $(PDM_SO) example/openssl/ecdh
	LD_PRELOAD=./$(PDM_SO) ./example/openssl/ecdh 2

run-ecdsa: $(PDM_SO) example/openssl/ecdsa
	LD_PRELOAD=./$(PDM_SO) ./example/openssl/ecdsa 2

run-rsa: $(PDM_SO) example/openssl/rsa
	LD_PRELOAD=./$(PDM_SO) ./example/openssl/rsa 2

run-aes: $(PDM_SO) example/wolfssl/aes
	LD_PRELOAD=./$(PDM_SO) ./example/wolfssl/aes

run-eddsa: $(PDM_SO) example/wolfssl/eddsa
	LD_PRELOAD=./$(PDM_SO) ./example/wolfssl/eddsa

clean:
	rm -f $(ALL_BINS) $(PDM_SO)