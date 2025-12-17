//gcc -O0 -fPIC -shared -o PDM-scheme6.so PDM-scheme6.c -lpthread -fno-stack-protector -fno-builtin -fno-jump-tables -fno-common

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <x86intrin.h>
#include <sched.h>
#include <xmmintrin.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <stdbool.h>

#define CACHE_LINE 64
#define PAGE_SIZE 4096
#define NUM_PAGES 2
#define START_ADDR 0x7ffff7fc5000
#define SIZE NUM_PAGES*PAGE_SIZE
#define BATCH_SIZE 8
#define WAIT_TIME  1000000
#define PROBES_PER_SIZE SIZE/CACHE_LINE
#define ATTACK_COOLDOWN_SEC  2

// Monotonic time in nanoseconds (immune to wall-clock jumps)
static inline uint64_t mono_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static uint64_t next_attack_ok_ns = 0;

static long long l1_p[NUM_PAGES]={0}, l3_p[NUM_PAGES]={0},
                 m_p [NUM_PAGES]={0}, bm_p[NUM_PAGES]={0};
static size_t    cnt_p[NUM_PAGES]={0};

bool header_printed = false;
void print_ratios_csv(const char* timeStr, float l1hitratio, float l3hitratio, float missratio, float bigmissratio, 
                  float l1hitratio2, float l3hitratio2, float missratio2, float bigmissratio2) {
    
    // Print the header row once
    if (!header_printed) {
        printf("Datetime,L1Hit,L3Hit,Miss,BigMiss,L1Hit2,L3Hit2,Miss2,BigMiss2\n");
        header_printed = true;
    }

    // Print the values as CSV
    printf("%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
           timeStr, l1hitratio, l3hitratio, missratio, bigmissratio,
           l1hitratio2, l3hitratio2, missratio2, bigmissratio2);
}


void print_ratios(const char* timeStr, size_t batch_offset, float l1hitratio, float l3hitratio, float missratio, float bigmissratio, 
                  float l1hitratio2, float l3hitratio2, float missratio2, float bigmissratio2) {
    printf("%s", timeStr);
    printf(" l1hit: %6.2f ** l3hit: %6.2f  ** miss: %6.2f ** bigmiss: %6.2f", l1hitratio, l3hitratio, missratio, bigmissratio);
    printf(" ===== ");
    printf( " l1hit2: %6.2f ** l3hit2: %6.2f ** miss2: %6.2f ** bigmiss2: %6.2f", l1hitratio2, l3hitratio2, missratio2, bigmissratio2);
    printf(" ** page_number: %zu", batch_offset);
    printf("\n");
}

uintptr_t get_shared_secret_address(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(path, "r");
    if (!maps_file) {
        perror("Failed to open memory map file");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        if (strstr(line, "shared_secret") && strstr(line, "rw-s")) {
            char *dash_pos = strchr(line, '-');
            if (dash_pos) {
                *dash_pos = '\0';
                uintptr_t start_addr = strtoull(line, NULL, 16);
                fclose(maps_file);
                return start_addr;
            }
        }
    }

    fclose(maps_file);
    fprintf(stderr, "Failed to find 'shared_secret' in memory map.\n");
    return 0;
}


int attackPrinted, counter = 0;

void* PDM_Probing(void* arg) {
    // sleep(2);

    uintptr_t start_addr = get_shared_secret_address(getpid());
    printf("Start Address Extracted by PDM: 0x%lx\n", start_addr);

    size_t probes1 = 0;
    size_t i = 0;
    size_t busycount = 0;
    while (1) {
        // printf(" ** i: %zu \n", i);
        uint64_t t0 = __rdtsc();
        size_t   j  = 0;
        size_t   busycount  = 0;
        while (__rdtsc() - t0 < WAIT_TIME) {
            size_t off = i*CACHE_LINE + j*PAGE_SIZE;
            if (off >= SIZE){
                // asm volatile("pause");
                nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 2}, NULL);
                // busycount++;
                // printf(" ** busycount: %zu \n", busycount);
                continue;
            }
            uint8_t *ptr = (uint8_t*)(start_addr + off);
            asm volatile("mfence");
            asm volatile("movq (%0), %%rax" :: "r"(ptr) : "rax");
            asm volatile("mfence");
            j++;
            // printf(" ** j: %zu \n", j);
            // printf(" ** busycount: %zu \n", busycount);
        }

        /* ---- RELOAD every line we just touched (i … i+j-1) ---- */
        
        for (size_t k = 0; k < j; k++) {
            size_t roff = i*CACHE_LINE + k*PAGE_SIZE;
            uint8_t *rptr = (uint8_t*)(start_addr + roff);
            asm volatile("mfence");
            uint64_t t1 = __rdtsc();
            asm volatile("mfence");
            asm volatile("movq (%0), %%rax" :: "r"(rptr) : "rax");
            asm volatile("mfence");
            uint64_t delta = __rdtsc() - t1;
            asm volatile("mfence");
            probes1++;

            size_t page = roff / PAGE_SIZE;
            if      (delta < 100)  l1_p[page] ++;
            else if (delta < 230)  l3_p[page] ++;
            else if (delta < 450)  m_p [page] ++;
            else                   bm_p[page]++;
            cnt_p[page]++;
            for (size_t p = 0; p < NUM_PAGES; p++) {
                if (cnt_p[p] == BATCH_SIZE) {   
                    /* time-stamp just like original code */
                    char timeStr[20];
                    struct timeval tv;
                    time_t now;
                    gettimeofday(&tv, NULL);
                    now = tv.tv_sec;
                    struct tm *tm_now = localtime(&now);
                    strftime(timeStr, sizeof(timeStr), "%H:%M:%S", tm_now);
                    snprintf(timeStr + 8, sizeof(timeStr) - 8, ".%03ld", tv.tv_usec / 1000);

                    double l1r  = 100.0*l1_p[p]/BATCH_SIZE;
                    double l3r  = 100.0*l3_p[p]/BATCH_SIZE;
                    double mr   = 100.0*m_p [p]/BATCH_SIZE;
                    double bmr  = 100.0*bm_p[p]/BATCH_SIZE;
                    /* second-round ratios not used yet → zeros */
                    // print_ratios(timeStr, p, l1r,l3r,mr,bmr,0,0,0,0);

                    int attack = (l1r <= 50);
                    uint64_t now_ns = mono_now_ns();

                    if (attack && !attackPrinted) {
                        printf("\nAttack detected at %s\n", timeStr);
                        attackPrinted = 1;
                    } else if (!attack && attackPrinted) {
                        counter++;
                    }

                    if (counter>= 2){
                        attackPrinted = 0;
                        counter = 0;
                    }
                        

                    if (l1r <= 90)
                        usleep(600);

                    /* reset this page’s mini-counters */
                    l1_p[p]=l3_p[p]=m_p[p]=bm_p[p]=cnt_p[p]=0;
                }
            }
        }

        // printf(" ** j++ to i: %zu \n", j);
        // i += j;
        i++;
        if (i>=64)
            i=0;

        // printf(" ** probes1: %zu \n", probes1);
    
        probes1 = 0;
    }
    return NULL;
}

__attribute__((constructor))
void init_library() {
    int N = 1;
    pthread_t tids[N];
    pthread_attr_t attr1;
    struct sched_param param1;

    pthread_attr_init(&attr1);
    param1.sched_priority = sched_get_priority_max(SCHED_OTHER);
    pthread_attr_setschedpolicy(&attr1, SCHED_FIFO); 
    pthread_attr_setschedparam(&attr1, &param1);

    for (int i = 0; i < N; i++) {
        if (pthread_create(&tids[i], &attr1, PDM_Probing, NULL) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }

    pthread_attr_destroy(&attr1);
}