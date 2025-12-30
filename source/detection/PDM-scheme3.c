#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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


// ---- Address selection mode ----
// Uncomment exactly ONE of these
#define USE_FIXED_START_ADDR
// #define USE_PROC_MAPS

#define START_ADDR 0x7ffff6fdf000
#define SIZE 1024

#define BATCH_SIZE 8
#define CACHE_LINE 64
#define PAGE_SIZE 4096
#define PROBE_ROUND_SIZE SIZE/CACHE_LINE
#define WORD_SIZE sizeof(long) // Typically 8 bytes on a 64-bit architecture
#define NUM_WORDS (CACHE_LINE / WORD_SIZE) // Number of words in the block

// Cache Utils
uint64_t rdtsc() {
  uint64_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
}

void maccess(void* p)
{
  asm volatile ("movq (%0), %%rax\n"
    :
    : "c" (p)
    : "rax");
}

void flush(void* p) {
    asm volatile ("clflush 0(%0)\n"
      :
      : "c" (p)
      : "rax");
}


bool header_printed = false; // Global flag to print the header only once
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
    printf(" ** batch_offset: %zu", batch_offset);
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

void* PDM_Probing(void* arg) {

    uintptr_t start_addr = START_ADDR;
    size_t total_size = SIZE;

    #ifdef USE_FIXED_START_ADDR
        start_addr = START_ADDR;
    #elif defined(USE_PROC_MAPS)
        start_addr = get_shared_secret_address(getpid());
    #else
    #error "You must define either USE_FIXED_START_ADDR or USE_PROC_MAPS"
    #endif


    printf("Start Address Extracted by PDM: 0x%lx\n", start_addr);
    size_t batch_offset = 0;   // Offset (in bytes) for the current batch
    size_t addresses_per_batch = BATCH_SIZE;  // Number of addresses to probe per batch

    // Counters for round 1 (ACCESS+RELOAD)
    long long l1_hit = 0, l3_hit = 0, miss = 0, bigmiss = 0;
    // Counters for round 2 (FLUSH+RELOAD)
    long long l1_hit2 = 0, l3_hit2 = 0, miss2 = 0, bigmiss2 = 0;

    struct timespec start, end;
    long long elapsed_ns;
    while (1) {
        // ---- First Round: ACCESS + RELOAD ----
        // clock_gettime(CLOCK_MONOTONIC, &start);
        for (size_t i = 0; i < addresses_per_batch; i++) {
            uint8_t *ptr = (uint8_t*)(start_addr + batch_offset + i * CACHE_LINE);
            // printf("Probing address : 0x%lx\n", ptr);
            asm volatile ("mfence");
            maccess(ptr);
            asm volatile ("mfence");
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 1000000}, NULL);
            sched_yield();
            size_t timeDelta = rdtsc();
            maccess(ptr);
            size_t delta = rdtsc() -  timeDelta;
            // printf("%zu\n", delta);

            if (delta < 500)
                l1_hit++;
            else if (delta < 700)
                l3_hit++;
            else if (delta < 1000)
                miss++;
            else
                bigmiss++;
        }

        // ---- Second Round: FLUSH + RELOAD ----
        for (size_t i = 0; i < addresses_per_batch; i++) {
            uint8_t *ptr = (uint8_t*)(start_addr + batch_offset + i * CACHE_LINE);
            
            flush(ptr);
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 300000}, NULL);
            size_t time = rdtsc();
            maccess(ptr);
            size_t delta = rdtsc() - time;
            // printf("%zu\n", delta);

            if (delta < 500)
                l1_hit2++;
            else if (delta < 700)
                l3_hit2++;
            else if (delta < 1000)
                miss2++;
            else
                bigmiss2++;
        }
        // clock_gettime(CLOCK_MONOTONIC, &end);

        // ---- Compute ratios based on the current batch ----
        double l1hitratio    = (double)l1_hit    / addresses_per_batch * 100;
        double l3hitratio    = (double)l3_hit    / addresses_per_batch * 100;
        double missratio     = (double)miss      / addresses_per_batch * 100;
        double bigmissratio  = (double)bigmiss   / addresses_per_batch * 100;
        double l1hitratio2   = (double)l1_hit2   / addresses_per_batch * 100;
        double l3hitratio2   = (double)l3_hit2   / addresses_per_batch * 100;
        double missratio2    = (double)miss2     / addresses_per_batch * 100;
        double bigmissratio2 = (double)bigmiss2  / addresses_per_batch * 100;

        // Get current time as a formatted string
        char timeStr[20];
        struct timeval tv;
        time_t now;
        gettimeofday(&tv, NULL);
        now = tv.tv_sec;
        struct tm *tm_now = localtime(&now);
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", tm_now);
        snprintf(timeStr + 8, sizeof(timeStr) - 8, ".%03ld", tv.tv_usec / 1000);

        // Print probing results
        // print_ratios_csv(timeStr, l1hitratio, l3hitratio, missratio, bigmissratio, l1hitratio2, l3hitratio2, missratio2, bigmissratio2);
        print_ratios(timeStr, batch_offset, l1hitratio, l3hitratio, missratio, bigmissratio,l1hitratio2, l3hitratio2, missratio2, bigmissratio2);

        
        // Reset counters for the next batch
        l1_hit = l3_hit = miss = bigmiss = 0;
        l1_hit2 = l3_hit2 = miss2 = bigmiss2 = 0;

        // Update batch offset: move to the next batch
        batch_offset += addresses_per_batch * CACHE_LINE;
        if (batch_offset >= total_size)
            batch_offset = 0;
    }
    return NULL;
}

__attribute__((constructor))
void init_library() {
    pthread_t tids;
    pthread_attr_t attr1;
    struct sched_param param1;

    pthread_attr_init(&attr1);
    param1.sched_priority = sched_get_priority_max(SCHED_OTHER);
    pthread_attr_setschedpolicy(&attr1, SCHED_FIFO); 
    pthread_attr_setschedparam(&attr1, &param1);

    if (pthread_create(&tids, &attr1, PDM_Probing, NULL) != 0) {
        perror("pthread_create");
        exit(1);
    }

    pthread_attr_destroy(&attr1);
}
