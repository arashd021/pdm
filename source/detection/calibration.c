#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>

#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))

size_t array[5*1024];

#define BIN_SIZE 5
#define N_BINS   400   // 400*5 = 2000 cycles coverage
size_t hit_histogram[N_BINS];
size_t miss_histogram[N_BINS];


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

size_t onlyreload(void* addr)
{
  size_t time = rdtsc();
  maccess(addr);
  size_t delta = rdtsc() - time;
  return delta;
}

size_t flushandreload(void* addr)
{
  size_t time = rdtsc();
  maccess(addr);
  size_t delta = rdtsc() - time;
  flush(addr);
  return delta;
}

static size_t percentile_from_hist(const size_t *hist, size_t n_bins,
                                   size_t bin_size, double p)
{
  // p in [0,1], e.g., 0.995 for 99.5%
  size_t total = 0;
  for (size_t i = 0; i < n_bins; ++i) total += hist[i];
  if (total == 0) return 0;

  size_t target = (size_t)(p * (double)total);
  if (target >= total) target = total - 1;

  size_t cum = 0;
  for (size_t i = 0; i < n_bins; ++i) {
    cum += hist[i];
    if (cum > target) return i * bin_size;
  }
  return (n_bins - 1) * bin_size;
}


int main(int argc, char** argv)
{
  memset(array,-1,5*1024*sizeof(size_t));
  maccess(array + 2*1024);
  sched_yield();
  for (int i = 0; i < 4*1024*1024; ++i)
  {
    size_t d = onlyreload(array+2*1024);
    hit_histogram[MIN(N_BINS-1, d / BIN_SIZE)]++;
    sched_yield();
  }
  flush(array+1024);
  for (int i = 0; i < 4*1024*1024; ++i)
  {
    size_t d = flushandreload(array+2*1024);
    miss_histogram[MIN(N_BINS-1, d / BIN_SIZE)]++;
    sched_yield();
  }
  
    printf(".\n");

    // ---- Print histograms + gather key indices ----
    size_t hit_max = 0, hit_max_i = 0;
    size_t miss_min_i = 0;
    size_t miss_max_i = 0;

    for (int i = 0; i < N_BINS; ++i)
    {
      printf("%4d: %10zu %10zu\n", i * BIN_SIZE, hit_histogram[i], miss_histogram[i]);


      if (hit_histogram[i] > hit_max) {
        hit_max = hit_histogram[i];
        hit_max_i = i;
      }

      // First "real" miss bin (avoid noise); keep your old heuristic
      if (miss_histogram[i] > 3 && miss_min_i == 0)
        miss_min_i = i;

      // Largest observed miss bin (for bigmiss threshold)
      if (miss_histogram[i] > 0)
        miss_max_i = i;
    }

    // Sanity message (same spirit as original)
    if (miss_min_i > hit_max_i + 4)
      printf("Flush+Reload possible!\n");
    else if (miss_min_i > hit_max_i + 2)
      printf("Flush+Reload probably possible!\n");
    else if (miss_min_i < hit_max_i + 2)
      printf("Flush+Reload maybe not possible!\n");
    else
      printf("Flush+Reload not possible!\n");

    // ---- 1) T_L1: split L1 vs L3-ish within hit_histogram ----
    // Find a "second peak" after the main peak but before misses kick in.
    size_t search_end = (miss_min_i > 0 ? miss_min_i : 80);
    size_t second_peak_i = 0;
    size_t second_peak = 0;

    if (hit_max_i + 2 < search_end) {
      for (size_t i = hit_max_i + 2; i < search_end; ++i) {
        if (hit_histogram[i] > second_peak) {
          second_peak = hit_histogram[i];
          second_peak_i = i;
        }
      }
    }

    // Pick valley between the two peaks (min hit count)
    size_t T_L1_i = hit_max_i + 1; // fallback
    if (second_peak_i > hit_max_i + 2 && second_peak > hit_max / 20) { // >=5% of main peak
      size_t valley_i = hit_max_i + 1;
      size_t valley_v = (size_t)-1;

      for (size_t i = hit_max_i + 1; i < second_peak_i; ++i) {
        if (hit_histogram[i] < valley_v) {
          valley_v = hit_histogram[i];
          valley_i = i;
        }
      }
      T_L1_i = valley_i;
    } else {
      T_L1_i = hit_max_i + 1;
      if (T_L1_i >= 79) T_L1_i = 79;
    }

    // ---- 2) T_L3: split L3-ish vs memory miss using both histograms (your original method) ----
    size_t start_i = (second_peak_i > hit_max_i ? second_peak_i : hit_max_i);
    if (start_i >= 79) start_i = 79;

    size_t min_sum = (size_t)-1;
    size_t T_L3_i = start_i;

    if (miss_min_i > start_i + 1) {
      for (size_t i = start_i; i < miss_min_i; ++i) {
        size_t s = hit_histogram[i] + miss_histogram[i];
        if (s < min_sum) {
          min_sum = s;
          T_L3_i = i;
        }
      }
    } else {
      // fallback if the "miss starts" too early / not detected
      T_L3_i = (start_i + 2 < 80) ? (start_i + 2) : 79;
    }

    // ---- 3) T_MISS: largest observed miss bucket -> beyond this is bigmiss ----
    size_t T_MISS_i = miss_max_i;
    

    size_t T_L1   = T_L1_i   * 5;
    size_t T_L3   = T_L3_i   * 5;
    // size_t T_MISS = T_MISS_i * 5;
    size_t T_MISS = percentile_from_hist(miss_histogram, N_BINS, BIN_SIZE, 0.9);


    printf("\n=== 4-bucket thresholds (calibrated) ===\n");
    printf("Use as:\n");
    printf("  if (delta < %zu)                l1_hit2++;\n", T_L1);
    printf("  else if (delta < %zu)           l3_hit2++;\n", T_L3);
    printf("  else if (delta < %zu)           miss2++;\n", T_MISS);
    printf("  else                            bigmiss2++;\n");

    printf("\nSuggested thresholds:\n");
    printf("  T_L1   = %zu\n", T_L1);
    printf("  T_L3   = %zu\n", T_L3);
    printf("  T_MISS = %zu\n", T_MISS);

    return (int)T_L3;

}
