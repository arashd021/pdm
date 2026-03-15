// Victim application based on Jan Wichelmann's code for CipherFix => https://github.com/UzL-ITS/cipherfix
// gcc -o aes aes.c -O2 -rdynamic -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -lcapstone -pthread
// (use -DDEBUG for debugging information)

#define _GNU_SOURCE
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/mman.h>
#include <inttypes.h>
#define CLOCK CLOCK_MONOTONIC
#define PAGE_SZ 4096

__attribute__((weak)) void install_guard(void *addr, size_t len);
bool disable_secret = true;
static void die(const char *msg) { perror(msg); exit(EXIT_FAILURE); }

/* ---------- AES-GCM test material ---------- */
// unsigned char key[16] = { 0 };          /* 128-bit zero key   */
// unsigned char key[24] = { 0 };          /* 192-bit zero key */
unsigned char key[32] = { 0 };          /* 256-bit zero key */
unsigned char iv [16] = { 0 };          /* 128-bit zero nonce */

/* message */
unsigned char m[16] = {
    0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1,
    0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d
};

static Aes *aesCtx;

static void dump(const char *lbl, const uint8_t *p, size_t n)
{
    printf("%s @%p :", lbl, p);
    for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
    puts("");
}

void cf_init_target(void)
{
    int ret;

    ret = wc_AesInit(aesCtx, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "wc_AesInit failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }

    ret = wc_AesGcmSetKey(aesCtx, key, sizeof(key));
    if (ret != 0) {
        fprintf(stderr, "wc_AesGcmSetKey failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
}

void cf_run_target(void)
{
    //AES
    unsigned char *cipher = malloc(sizeof(m));
    unsigned char *tag = malloc(16);

    if (!cipher) die("malloc cipher");
    if (!tag) die("malloc tag");

    wc_AesGcmEncrypt(aesCtx, cipher, m, sizeof(m), iv, sizeof(iv), tag, 16, NULL, 0);

    free(cipher);
    free(tag);

    // Multi-round
    // int pLen = 16 * 1000;
    // unsigned char *p = malloc(pLen);
    // unsigned char *cipher = malloc(pLen);
    // unsigned char *tag = malloc(16);

    // if (!p) die("malloc p");
    // if (!cipher) die("malloc cipher");
    // if (!tag) die("malloc tag");

    // for(int i = 0; i < pLen; i += 16)
    //     memcpy(p + i, m, 16);

    // int ret = wc_AesGcmEncrypt(aesCtx, cipher, p, pLen, iv, sizeof(iv), tag, 16, NULL, 0);
    // if (ret != 0) {
    //     fprintf(stderr, "wc_AesGcmEncrypt failed: %d\n", ret);
    //     free(p);
    //     free(cipher);
    //     free(tag);
    //     exit(EXIT_FAILURE);
    // }

    // free(cipher);
    // free(tag);
    // free(p);
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

static inline double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
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

    aesCtx = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (aesCtx == MAP_FAILED) die("mmap aes page");

    cf_init_target();
    
    printf("[victim] secret  base = %p  len = %zu bytes\n",
           (void *)aesCtx, sizeof *aesCtx);

    dump("[victim] secret BEFORE guarding", (uint8_t*)aesCtx, sizeof *aesCtx);

    if (disable_secret) {
        printf("[victim] guarding key\n");
        if (install_guard) {
            install_guard(aesCtx, sizeof *aesCtx);
        } else {
            fprintf(stderr, "[victim] install_guard not found (run with LD_PRELOAD?)\n");
        }
    }

    int n = 1000;
    printf("Running %d rounds\n", n);
    
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
