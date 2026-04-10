#define _GNU_SOURCE
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))

#define BIN_SIZE 5
#define N_BINS 400
#define CALIBRATION_ROUNDS 9
#define CALIBRATION_SAMPLES 12000
#define WARMUP_SAMPLES 1024
#define CACHE_LINE_SIZE 64
#define ADDRESS_POOL_SIZE 64
#define PRIVATE_CACHE_EVICT_BYTES (1024 * 1024)
#define FAST_HIT_GUARD_BINS 2
#define T_L1_ROUND_TO 25
#define T_L3_ROUND_TO 50
#define T_MISS_ROUND_TO 100

static size_t array[5 * 1024];
static uint8_t eviction_buffer[PRIVATE_CACHE_EVICT_BYTES];

static uint64_t rdtsc(void)
{
  uint64_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d << 32) | a;
  asm volatile ("mfence");
  return a;
}

static void maccess(void* p)
{
  asm volatile ("movq (%0), %%rax\n"
    :
    : "r" (p)
    : "rax", "memory");
}

static void flush(void* p)
{
  asm volatile ("clflush 0(%0)\n"
    :
    : "r" (p)
    : "memory");
  asm volatile ("mfence");
}

static size_t timed_reload(void* addr)
{
  size_t start = rdtsc();
  maccess(addr);
  return rdtsc() - start;
}

static inline void* sample_addr(size_t sample_index)
{
  size_t slot = (sample_index * 17) % ADDRESS_POOL_SIZE;
  return (uint8_t *)array + slot * CACHE_LINE_SIZE;
}

static void evict_private_caches(void)
{
  for (size_t i = 0; i < PRIVATE_CACHE_EVICT_BYTES; i += CACHE_LINE_SIZE)
    maccess(eviction_buffer + i);
}

static size_t measure_l1(void* addr)
{
  maccess(addr);
  return timed_reload(addr);
}

static size_t measure_l3(void* addr)
{
  maccess(addr);
  evict_private_caches();
  return timed_reload(addr);
}

static size_t measure_miss(void* addr)
{
  flush(addr);
  return timed_reload(addr);
}

static void pin_to_current_cpu(void)
{
  cpu_set_t set;
  int cpu = sched_getcpu();

  if (cpu < 0)
    cpu = 0;

  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  if (sched_setaffinity(0, sizeof(set), &set) != 0)
    fprintf(stderr, "warning: failed to pin calibration to cpu %d\n", cpu);
}

static size_t percentile_from_hist(const size_t *hist, double p)
{
  size_t total = 0;
  for (size_t i = 0; i < N_BINS; ++i)
    total += hist[i];

  if (total == 0)
    return 0;

  size_t target = (size_t)(p * (double)(total - 1));
  size_t cum = 0;
  for (size_t i = 0; i < N_BINS; ++i) {
    cum += hist[i];
    if (cum > target)
      return i * BIN_SIZE;
  }

  return (N_BINS - 1) * BIN_SIZE;
}

static size_t median_of(size_t *values, size_t count)
{
  for (size_t i = 1; i < count; ++i) {
    size_t v = values[i];
    size_t j = i;
    while (j > 0 && values[j - 1] > v) {
      values[j] = values[j - 1];
      --j;
    }
    values[j] = v;
  }

  return values[count / 2];
}

static size_t round_up_to(size_t value, size_t quantum)
{
  if (quantum == 0)
    return value;
  return ((value + quantum - 1) / quantum) * quantum;
}

static int build_constants_path(char *path, size_t path_sz)
{
  char exe_path[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (n < 0 || (size_t)n >= sizeof(exe_path))
    return -1;

  exe_path[n] = '\0';

  char *slash = strrchr(exe_path, '/');
  if (!slash)
    return -1;
  *slash = '\0';

  if (snprintf(path, path_sz, "%s/../constants.h", exe_path) >= (int)path_sz)
    return -1;

  return 0;
}

static int write_updated_constants(const char *constants_path,
                                   size_t t_l1,
                                   size_t t_l3,
                                   size_t t_miss)
{
  char tmp_path[PATH_MAX];
  FILE *in = fopen(constants_path, "r");
  if (!in)
    return -1;

  if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", constants_path) >= (int)sizeof(tmp_path)) {
    fclose(in);
    return -1;
  }

  FILE *out = fopen(tmp_path, "w");
  if (!out) {
    fclose(in);
    return -1;
  }

  char line[1024];
  int saw_l1 = 0, saw_l3 = 0, saw_miss = 0;
  while (fgets(line, sizeof(line), in)) {
    if (strncmp(line, "#define THR_L1", 14) == 0) {
      fprintf(out, "#define THR_L1   %zu\n", t_l1);
      saw_l1 = 1;
    } else if (strncmp(line, "#define THR_L3", 14) == 0) {
      fprintf(out, "#define THR_L3   %zu\n", t_l3);
      saw_l3 = 1;
    } else if (strncmp(line, "#define THR_MISS", 16) == 0) {
      fprintf(out, "#define THR_MISS %zu\n", t_miss);
      saw_miss = 1;
    } else {
      fputs(line, out);
    }
  }

  fclose(in);

  if (fclose(out) != 0 || !saw_l1 || !saw_l3 || !saw_miss) {
    unlink(tmp_path);
    return -1;
  }

  if (rename(tmp_path, constants_path) != 0) {
    unlink(tmp_path);
    return -1;
  }

  return 0;
}

static void warmup(void)
{
  for (size_t i = 0; i < WARMUP_SAMPLES; ++i) {
    void *addr = sample_addr(i);
    (void)measure_l1(addr);
    (void)measure_l3(addr);
    (void)measure_miss(addr);
  }
}

static void fill_histogram(size_t *hist, size_t (*measure)(void*))
{
  memset(hist, 0, N_BINS * sizeof(*hist));
  for (size_t i = 0; i < CALIBRATION_SAMPLES; ++i) {
    void *addr = sample_addr(i);
    size_t d = measure(addr);
    hist[MIN(N_BINS - 1, d / BIN_SIZE)]++;
  }
}

int main(void)
{
  size_t l1_histogram[N_BINS];
  size_t l3_histogram[N_BINS];
  size_t miss_histogram[N_BINS];
  size_t t_l1_rounds[CALIBRATION_ROUNDS];
  size_t t_l3_rounds[CALIBRATION_ROUNDS];
  size_t t_miss_rounds[CALIBRATION_ROUNDS];
  char constants_path[PATH_MAX];

  memset(array, -1, sizeof(array));
  memset(eviction_buffer, 1, sizeof(eviction_buffer));
  pin_to_current_cpu();
  warmup();

  for (size_t round = 0; round < CALIBRATION_ROUNDS; ++round) {
    fill_histogram(l1_histogram, measure_l1);
    fill_histogram(l3_histogram, measure_l3);
    fill_histogram(miss_histogram, measure_miss);

    size_t l1_upper = percentile_from_hist(l1_histogram, 0.999);
    size_t fast_hit_upper = percentile_from_hist(l3_histogram, 0.995);
    size_t miss_core_low = percentile_from_hist(miss_histogram, 0.10);
    size_t miss_core_high = percentile_from_hist(miss_histogram, 0.90);
    size_t miss_spread = MAX(BIN_SIZE, miss_core_high - miss_core_low);

    size_t t_l1 = MAX(l1_upper + BIN_SIZE, fast_hit_upper + FAST_HIT_GUARD_BINS * BIN_SIZE);
    size_t t_l3 = MAX(t_l1 + BIN_SIZE, miss_core_high + miss_spread);
    size_t t_miss = MAX(t_l3 + BIN_SIZE, miss_core_high + 2 * (t_l3 - t_l1));

    t_l1_rounds[round] = t_l1;
    t_l3_rounds[round] = t_l3;
    t_miss_rounds[round] = t_miss;
  }

  size_t T_L1 = median_of(t_l1_rounds, CALIBRATION_ROUNDS);
  size_t T_L3 = median_of(t_l3_rounds, CALIBRATION_ROUNDS);
  size_t T_MISS = median_of(t_miss_rounds, CALIBRATION_ROUNDS);

  if (T_L3 <= T_L1)
    T_L3 = T_L1 + BIN_SIZE;
  if (T_MISS <= T_L3)
    T_MISS = T_L3 + BIN_SIZE;

  T_L1 = round_up_to(T_L1, T_L1_ROUND_TO);
  T_L3 = round_up_to(MAX(T_L3, T_L1 + BIN_SIZE), T_L3_ROUND_TO);
  T_MISS = round_up_to(MAX(T_MISS, T_L3 + BIN_SIZE), T_MISS_ROUND_TO);

  printf("\n=== 4-bucket thresholds (calibrated, stable mode) ===\n");
  printf("Measured as delta = rdtsc(); maccess(addr); rdtsc() - delta.\n");
  printf("Calibration is pinned to one CPU and reports the median of %d rounds.\n",
         CALIBRATION_ROUNDS);
  printf("Thresholds are widened from that machine's measured fast-hit and miss spread, without absolute floors.\n");
  printf("These thresholds include rdtsc measurement overhead and can be copied directly into constants.h.\n");

  printf("\nSuggested thresholds:\n");
  printf("  T_L1   = %zu\n", T_L1);
  printf("  T_L3   = %zu\n", T_L3);
  printf("  T_MISS = %zu\n", T_MISS);

  if (build_constants_path(constants_path, sizeof(constants_path)) != 0 ||
      write_updated_constants(constants_path, T_L1, T_L3, T_MISS) != 0) {
    fprintf(stderr, "\nFailed to update constants.h automatically.\n");
    return 1;
  }

  printf("\nUpdated %s\n", constants_path);

  return 0;
}
