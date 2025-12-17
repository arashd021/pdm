// compile: gcc victim.c -o vicim -lrt
// usage with PDM: sudo taskset -c 0 sh -c 'LD_PRELOAD=PDM.so ./victim'

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <errno.h>
#include <sys/time.h>

#define SIZE 4096

unsigned long long fib(int n) {
    if (n <= 1)
        return n;
    return fib(n-1) + fib(n-2);
}

void busy_wait(uint64_t delay_cycles) {
    uint64_t start = __rdtsc();
    while (__rdtsc() - start < delay_cycles) {
        // Busy-wait loop
    }
}

int main(int argc, char *argv[]) {

    // Create a shared memory object
    const char *shm_name = "/shared_secret";

    // if (shm_unlink(shm_name) == -1 && errno != ENOENT) {
    //     perror("shm_unlink (stale root-owned object?)");
    //     exit(EXIT_FAILURE);
    // }

    int shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    // int shm_fd = shm_open(shm_name, O_RDONLY, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(1);
    }

    // Set the size of the shared memory object
    int len = SIZE;
    if (ftruncate(shm_fd, len) == -1) {
        perror("ftruncate");
        exit(1);
    }

    // Map the shared memory object in the address space
    char *secret = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (secret == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // Generate random characters from 'A' to 'Z' and store them in the shared memory
    srand(time(NULL));
    for (int i = 0; i < len; i++) {
        secret[i] = 'A' + rand() % 26;
    }
    secret[len - 1] = '\0'; // null-termination

    printf("The virtual address of 'secret' in shared memory is: %p\n", (void*)secret);



    while (1) {
        for (size_t i = 0; i < len - 8; i += 64) {
            asm volatile("movq (%0), %%rax\n" : : "r"(&secret[i]) : "rax");
        }
        // nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 1000000}, NULL);
        volatile unsigned long long fibResult = fib(23);
    }

    munmap(secret, len);
    shm_unlink(shm_name);

    return 0;
}
