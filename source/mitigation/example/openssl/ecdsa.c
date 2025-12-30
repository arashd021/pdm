// Victim application based on Jan Wichelmann's code for CipherFix => https://github.com/UzL-ITS/cipherfix
// gcc -o ecdsa ecdsa.c -g -O0 -rdynamic -no-pie -fno-omit-frame-pointer -fno-stack-protector -maes -msse2 -march=native -lcrypto -lcapstone -pthread
// (use -DDEBUG for debugging information)

#define _GNU_SOURCE
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/mman.h>
#include <stdint.h>
#define CLOCK CLOCK_MONOTONIC
#include <openssl/crypto.h>


__attribute__((weak)) void install_guard(void *addr, size_t len);

int   g_pkey;
bool disable_secret = true;
static bool hook_enabled = false;
static bool secret_handed = false;
char *secret;

// Our own really simple and non-random number generator
static uint8_t randState[32] = { 0 };

static void dump(const char *lbl, const uint8_t *p, size_t n)
{
    printf("%s @%p :", lbl, p);
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

_Static_assert(sizeof(randState) == 32, "randState must be 32 bytes for SHA-256 based generator");

int DummyRandBytes(uint8_t* buf, int num)
{
    if (buf == NULL || num < 0) return 0;
    if (num == 0) return 1;

    const int chunkLen = (int)sizeof(randState);
    int offset = 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) return 0;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    while (offset < num)
    {
        // digest = SHA256(randState)
        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
        if (EVP_DigestUpdate(mdctx, randState, sizeof(randState)) != 1) {
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
        if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
            EVP_MD_CTX_free(mdctx);
            return 0;
        }

        // Overwrite randState with the digest (same semantics as before)
        // Assumes randState is 32 bytes. If it's larger, we only overwrite the first 32.
        const int to_state = (int)((digest_len < sizeof(randState)) ? digest_len : sizeof(randState));
        memcpy(randState, digest, to_state);

        // Output bytes (same chunking behavior as before)
        const int n = (num - offset < chunkLen) ? (num - offset) : chunkLen;
        memcpy(buf + offset, randState, n);
        offset += n;
    }

    EVP_MD_CTX_free(mdctx);
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


// Key (32 bytes → secp256k1 = 256-bit private key)
    // uint8_t key[32] = {
    //     0xb3, 0x21, 0xca, 0x3d, 0x67, 0xd6, 0x5b, 0xe3,
    //     0x9f, 0x8b, 0xdd, 0xdd, 0xb2, 0xea, 0x6b, 0xa0,
    //     0xab, 0x96, 0xd8, 0xac, 0x66, 0x03, 0x8d, 0x1e,
    //     0x5a, 0x8a, 0xbb, 0x50, 0xb6, 0x6b, 0x2d, 0x95
    // };

// // Key (48 bytes → secp384r1 = 384-bit private key)
uint8_t key[48] = {
    0x97, 0x3B, 0x45, 0xA2, 0x6F, 0x12, 0xE5, 0x9C,
    0x01, 0xBC, 0xDE, 0x34, 0x56, 0x78, 0x9A, 0xFB,
    0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
    0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
    0xDC, 0xFE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
};


// Message to sign.
unsigned char m[32] = { 0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d, 0x84, 0x78, 0x33, 0x2d, 0xf3, 0x5e, 0xe7, 0xa1, 0x15, 0x63, 0x71, 0x0b, 0x48, 0xec, 0x06, 0x1c   };

EC_KEY *eckey;
EC_GROUP *ecgroup;

static void die(const char *msg) { perror(msg); exit(EXIT_FAILURE); }
#define PAGE_SZ 4096



void cf_prepare_next(void)
{
    // Increment message
    for(int i = 0; i < sizeof(m); ++i)
    {
        unsigned char tmp = m[i] + 1;
        m[i] = tmp;
        if(tmp != 0)
            break;
    }
}


void cf_init_target(void)
{
    // 1) ban all external randomness
    RAND_set_rand_method(&rand_meth);

    // Allocate and initialize necessary data structures
    eckey = EC_KEY_new();
    if (eckey == NULL)
        printf("eckey is null\n");
    // ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    ecgroup = EC_GROUP_new_by_curve_name(NID_secp384r1);
    
    if (ecgroup == NULL)
        printf("ecgroup is null\n");
    if (!EC_KEY_set_group(eckey,ecgroup))
        printf("error setting group\n");

    // 6) generate the peer’s key for this round
    cf_prepare_next();
}

void cf_run_target(bool dumpResult)
{

    secret_handed = false;
    hook_enabled = true;
    if (!EC_KEY_oct2priv(eckey, secret, sizeof(key)))
        printf("oct2priv error\n");
    hook_enabled = false;
    
    int sigLen = ECDSA_size(eckey);
    unsigned char *sig = OPENSSL_malloc(sigLen);
    if(!ECDSA_sign(0, m, sizeof(m), sig, &sigLen, eckey))
        printf("signature error\n");

    OPENSSL_free(sig);
}


static void *secure_malloc(size_t sz,
                           const char *file, int line)
{
    (void)file; (void)line;

    /* Give the protected page exactly once per round */
    if (hook_enabled && !secret_handed && sz == sizeof(key)) {
        secret_handed = true;
        return secret;
    }
    return malloc(sz);
}

static void *secure_realloc(void *ptr, size_t sz,
                            const char *file, int line)
{
    (void)file; (void)line;

    /* OpenSSL never needs to grow the private‑key buffer;
       if it tries, refuse to move it. */
    if (ptr == secret)
        return secret;
    return realloc(ptr, sz);
}

static void secure_free(void *ptr,
                        const char *file, int line)
{
    (void)file; (void)line;

    if (ptr == secret) {           /* keep PKU page alive */
        secret_handed = false;     /* ready for next round */
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

    secret = mmap(NULL, PAGE_SZ,
                  PROT_READ|PROT_WRITE,
                  MAP_ANONYMOUS|MAP_PRIVATE,
                  -1, 0);
    if (secret == MAP_FAILED) die("mmap(secret)");
    // copy the 32-byte private key into that new page
    memcpy(secret, key, sizeof(key));

    cf_init_target();

    printf("[victim] secret  base = %p len = %d bytes\n",
           (void *)secret, 48);

    dump("secret BEFORE guarding", (uint8_t*)secret, 48);

    if (disable_secret) {
        printf("[victim] guarding key\n");
        if (install_guard) {
            install_guard(secret, PAGE_SZ);
        } else {
            fprintf(stderr, "[victim] install_guard not found (run with LD_PRELOAD?)\n");
        }
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
    printf("Execution time: %ld us -> %.3f ms\n", loop_us, loop_us/1000.0);

    return 0;
}
