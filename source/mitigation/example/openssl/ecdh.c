// Victim application based on Jan Wichelmann's code for CipherFix => https://github.com/UzL-ITS/cipherfix
// gcc -o ecdh ecdh.c ../../PDM-encrypt.c -g -O0 -no-pie -fno-omit-frame-pointer -fno-stack-protector -maes -msse2 -march=native -lcrypto -lcapstone -pthread -DPDM_MASKING=1
// (use -DDEBUG for debugging information)

#define _GNU_SOURCE
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <stdint.h>
#define CLOCK CLOCK_MONOTONIC
#include <openssl/crypto.h>


#define PAGE_SZ 4096
extern void install_guard(void *addr, size_t len);

bool disable_secret = true;
static bool hook_enabled = false;
static bool secret_handed = false;
char *secret;

static void die(const char *msg) { perror(msg); exit(EXIT_FAILURE); }

static uint8_t randState[32] = { 0 };

static void dump(const char *lbl, const uint8_t *p, size_t n)
{
    // printf("%s @%p :", lbl, p);
    printf("%s :", lbl);
    for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
    puts("");
}

int DummyRandAdd(const void* buf, int num, double randomness)
{
    // Completely replace random state
    int count = num;
    if(count > sizeof(randState))
        count = sizeof(randState);

    memset(randState, 0, sizeof(randState));
    memcpy(randState, buf, count);

    return 1;
}

int DummyRandSeed(const void* buf, int num)
{
    return DummyRandAdd(buf, num, num);
}

int DummyRandBytes(uint8_t* buf, int num)
{
    // Generate chunks
    int chunkLen = sizeof(randState);
    SHA256_CTX sha256;
    int offset = 0;
    for(int i = 0; i < num / chunkLen; ++i)
    {
        // Update state and copy
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, randState, sizeof(randState));
        SHA256_Final(randState, &sha256);
        memcpy(buf + offset, randState, chunkLen);

        offset += chunkLen;
    }

    // Generate last chunk
    if(offset < num)
    {
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, randState, sizeof(randState));
        SHA256_Final(randState, &sha256);
        memcpy(buf + offset, randState, num - offset);
    }

    return 1;
}

int DummyRandStatus(void)
{
    return 1;
}

RAND_METHOD rand_meth = {
    DummyRandSeed,
    DummyRandBytes,
    NULL,
    DummyRandAdd,
    DummyRandBytes,
    DummyRandStatus
};

EVP_PKEY *theirKey = NULL;

uint8_t ecdhOurD[] = { 0x49, 0x6b, 0xd0, 0xa7, 0xd4, 0xc5, 0xda, 0x01, 0x54, 0xe3, 0xa9, 0x91, 0x5d, 0xda, 0x43, 0xfd, 0xd5, 0x87, 0x67, 0x05, 0xb1, 0x6c, 0xd8, 0x21, 0x19, 0xc2, 0x81, 0x2e, 0x83, 0x61, 0x15, 0xf8 };
uint8_t ecdhOurQ[] = { 0x59, 0xa5, 0xeb, 0x93, 0x5e, 0x89, 0xfa, 0xa7, 0x94, 0x9d, 0xf0, 0xfa, 0x75, 0xbd, 0x05, 0x39, 0xc0, 0x43, 0x05, 0x92, 0xdb, 0x56, 0xe4, 0x84, 0x76, 0xfb, 0x75, 0x80, 0x6b, 0xfe, 0x21, 0x7a };
static const uint8_t secret_mask[32] __attribute__((aligned(32))) = {
    /*  0  1  2  3  4  5  6  7   8  9 10 11 12 13 14 15 */
       0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,
       0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,
       0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,
       0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5
};



static void hexdump(const char *lbl, const uint8_t *b, size_t n)
{
    printf("%s:", lbl);
    for (size_t i = 0; i < n; i++)  printf(" %02x", b[i]);
    putchar('\n');
}

void cf_prepare_next(void)
{
    if (theirKey) EVP_PKEY_free(theirKey);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    theirKey = NULL;
    if (!EVP_PKEY_keygen(pctx, &theirKey))
        printf("their keygen error\n");
}


void cf_init_target(void)
{
    // 1) ban all external randomness
    RAND_set_rand_method(&rand_meth);

    // 6) generate the peer’s key for this round
    cf_prepare_next();
}

void cf_run_target(bool dumpResult)
{
    hook_enabled = true;
    secret_handed = false;
    EVP_PKEY *ourKey = EVP_PKEY_new_raw_private_key(
                          EVP_PKEY_X25519,
                          NULL,
                          secret,
                          sizeof(ecdhOurD));
    hook_enabled = false;
    if (!ourKey) printf("our key alloc error\n");

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(ourKey, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_derive_set_peer(pctx, theirKey);

    size_t len = 32;
    unsigned char *secret_out = OPENSSL_malloc(len);
    if (!EVP_PKEY_derive(pctx, secret_out, &len))
        printf("dh error\n");
    
    // hexdump("shared secret", secret_out, len);

    OPENSSL_free(secret_out);
    EVP_PKEY_free(ourKey);
    EVP_PKEY_CTX_free(pctx);
}



static bool secret_in_use = false;          /* 0 = free, 1 = handed out */
/* ------------------------------------------------------------------ */
static void *secure_malloc(size_t sz,
                           const char *file, int line)
{
    (void)file; (void)line;

    /* Give the protected page **once**, when the scalar is duplicated */
    if (hook_enabled && !secret_handed && sz == sizeof(ecdhOurD)) {
        secret_in_use = true;
        return secret;                      /* guarded page */
    }
    return malloc(sz);                      /* everything else */
}

static void *secure_realloc(void *ptr,
                            size_t sz,
                            const char *file, int line)
{
    (void)file; (void)line;

    /* OpenSSL never reallocs the scalar; fall back */
    return (ptr == secret) ? secret : realloc(ptr, sz);
}

static void secure_free(void *ptr,
                        const char *file, int line)
{
    (void)file; (void)line;

    if (ptr == secret) {                    /* don’t un‑map the page */
        secret_in_use = false;              /* ready for next round  */
        return;
    }
    free(ptr);
}


void __attribute__((optimize("O0"))) foo()
{
    void *a = malloc(4);
    free(a);
}


int main(int argc, char *argv[])
{   
    CRYPTO_set_mem_functions(secure_malloc, secure_realloc, secure_free);
    if (argc != 2 || (argv[1][0] != '1' && argv[1][0] != '2')) {
        fprintf(stderr, "Usage: %s <mode>\n", argv[0]);
        fprintf(stderr, "  mode 1 = No Protection\n");
        fprintf(stderr, "  mode 2 = Protect Key\n");
        exit(EXIT_FAILURE);
    }
    
    struct timespec t0, t1, t2;
    clock_gettime(CLOCK, &t0);
    foo();

    int n = 10000;
    printf("Running %d rounds\n", n);

    bool perf = (argc >= 3 && strcmp(argv[2], "perf") == 0);
    // if (perf) printf("Performance mode\n");

    if (argc >= 2) {
        int mode = atoi(argv[1]);
        disable_secret = (mode == 2);
    }

    // allocate one page, copy our D into it
    secret = mmap(NULL, PAGE_SZ,
                  PROT_READ|PROT_WRITE,
                  MAP_ANONYMOUS|MAP_PRIVATE,
                  -1, 0);
    if (secret == MAP_FAILED) die("mmap(secret)");
    // copy the 32-byte private key into that new page
    memcpy(secret, ecdhOurD, sizeof(ecdhOurD));

    cf_init_target();

    printf("[victim] secret base = %p   len = %zu bytes\n", (void *)secret, sizeof(ecdhOurD));

    dump("[victim] secret BEFORE guarding", (uint8_t*)secret, sizeof(ecdhOurD));

    if (disable_secret) {
        printf("[victim] guarding key\n");
        install_guard(secret, PAGE_SZ);
    }

    cf_run_target(!perf || n==0);
    cf_prepare_next();
    clock_gettime(CLOCK, &t1);

    while (n-->0) {
        
        cf_run_target(!perf || n==0);
        cf_prepare_next();
        // nanosleep(&(struct timespec){.tv_sec=0,.tv_nsec=20000000}, NULL);
    }

    clock_gettime(CLOCK, &t2);
    long init_us = (t1.tv_sec - t0.tv_sec)*1000000 + (t1.tv_nsec - t0.tv_nsec)/1000;
    long loop_us = (t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_nsec - t1.tv_nsec)/1000;
    // printf("\nInit time: %ld us -> %.3f ms\n", init_us, init_us/1000.0);
    printf("Execution time : %ld us -> %.3f ms\n", loop_us, loop_us/1000.0);

    return 0;
}
