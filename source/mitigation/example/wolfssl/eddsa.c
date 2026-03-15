// Victim application based on Jan Wichelmann's code for CipherFix => https://github.com/UzL-ITS/cipherfix
//gcc -o eddsa-wlf eddsa-wlf.c handler-v6.c -O0 -fno-unwind-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer -fvisibility=hidden -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s -Wl,--build-id=none -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack  -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -lcapstone -pthread -mpku -DDEBUG

#define _GNU_SOURCE
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/mman.h>
#include <inttypes.h>
#define CLOCK CLOCK_MONOTONIC

static void die(const char *msg) { perror(msg); exit(EXIT_FAILURE); }

#define PAGE_SZ 4096
__attribute__((weak)) void install_guard(void *addr, size_t len);
bool disable_secret = true;

// ─────────────────────────────────────────────────────────────────────
// Secret key that is used for signature
unsigned char secretkey[32] = { 
    0x60, 0xea, 0x88, 0x4a, 0x8c, 0x32, 0x36, 0x0e,
    0xfd, 0xa4, 0x58, 0x0b, 0x30, 0x36, 0x9e, 0xac,
    0x4b, 0xd2, 0xc9, 0xbe, 0xfe, 0x43, 0xd9, 0x0f,
    0xdb, 0x80, 0xbb, 0xd8, 0xae, 0xc4, 0xa8, 0x78
};

// Hash to sign
unsigned char m[32] = {
    0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1,
    0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d,
    0x84, 0x78, 0x33, 0x2d, 0xf3, 0x5e, 0xe7, 0xa1,
    0x15, 0x63, 0x71, 0x0b, 0x48, 0xec, 0x06, 0x1c
};


static struct ed25519_key *k;
int error;

static void dump(const char *lbl, const uint8_t *p, size_t n)
{
    printf("%s @%p :", lbl, p);
    for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
    puts("");
}

void cf_init_target(void)
{
    wc_ed25519_init(k);
    if((error = wc_ed25519_import_private_only(secretkey, sizeof(secretkey), k)))
    {
        printf("Key import failed: %d %s\n", error, wc_GetErrorString(error));
        return;
    }

    uint8_t public[32] = { 0 };
    if((error = wc_ed25519_make_public(k, public, sizeof(public))))
    {
        printf("Public key generation failed: %d %s\n", error, wc_GetErrorString(error));
        return;
    }
    
    if((error = wc_ed25519_import_public(public, sizeof(public), k)))
    {
        printf("Public key import failed: %d %s\n", error, wc_GetErrorString(error));
        return;
    }

}


void cf_run_target(void)
{

    unsigned char *sm = malloc(64);
    if (!sm) die("malloc sm");
    word32 ssize = 64;
    if((error = wc_ed25519_sign_msg(m, sizeof(m), sm, &ssize, k)))
    {
        printf("Signature failed: %d %s\n", error, wc_GetErrorString(error));
        free(sm);
        return;
    }
    
    free(sm);
}

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

void __attribute__((optimize("O0"))) foo()
{
    void *a = malloc(4);
    free(a);
}

int main(int argc, char *argv[])
{   
    if (argc != 2 || (argv[1][0] != '1' && argv[1][0] != '2')) {
        fprintf(stderr, "Usage: %s <mode>\n", argv[0]);
        fprintf(stderr, "  mode 1 = No Protection\n");
        fprintf(stderr, "  mode 2 = Protect Key\n");
        exit(EXIT_FAILURE);
    }

    if (argc >= 2) {
        int mode = atoi(argv[1]);
        disable_secret = (mode == 2);
    }
    
    struct timespec t0, t1, t2;
    clock_gettime(CLOCK, &t0);
    foo();

    k = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (k == MAP_FAILED) die("mmap aes page");

    cf_init_target();

    printf("[victim] k  base = %p  len = %zu bytes\n",
        (void *)k, sizeof *k);

    dump("secret BEFORE guarding", (uint8_t*)k, sizeof *k);

    if (disable_secret) {
        printf("[victim] guarding key\n");
        if (install_guard) {
            install_guard(k, PAGE_SZ);
        } else {
            fprintf(stderr, "[victim] install_guard not found (run with LD_PRELOAD?)\n");
        }
    }

    int n = 1000;
    printf("Running %d rounds\n", n);


    if (argc >= 2) {
        int mode = atoi(argv[1]);
        disable_secret = (mode == 2);
    }

    cf_run_target();
    cf_prepare_next();
    clock_gettime(CLOCK, &t1);

    while (n-->0) {
        cf_run_target();
        cf_prepare_next();
    }

    clock_gettime(CLOCK, &t2);
    long init_us = (t1.tv_sec - t0.tv_sec)*1000000 + (t1.tv_nsec - t0.tv_nsec)/1000;
    long loop_us = (t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_nsec - t1.tv_nsec)/1000;
    // printf("\nInit time: %ld us -> %.3f ms\n", init_us, init_us/1000.0);
    printf("Execution time: %ld us -> %.3f ms\n", loop_us, loop_us/1000.0);

    return 0;
}