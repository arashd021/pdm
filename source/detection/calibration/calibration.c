#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../constants.h"

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
#define FR_REFINEMENT_PASSES 5
#define FR_GUIDED_ROUNDS 7
#define FR_SAMPLE_COUNT_PER_ROUND 256
#define FR_SAMPLE_COUNT (FR_GUIDED_ROUNDS * FR_SAMPLE_COUNT_PER_ROUND)
#define FR_SETTLE_USEC 250000
#define FR_INTERPASS_USEC 100000
#define FR_INTERROUND_USEC 50000
#define FR_SLEEP_NSEC 300000
#define FR_SHARED_NAME "/shared_secret"
#define FR_L3_GAP_MIN 50
#define FR_MISS_GAP_MIN 100

static size_t array[5 * 1024];
static uint8_t eviction_buffer[PRIVATE_CACHE_EVICT_BYTES];
static int pinned_cpu = 0;

struct fr_paths {
  char detection_dir[PATH_MAX];
  char example_dir[PATH_MAX];
  char victim_path[PATH_MAX];
  char attack_path[PATH_MAX];
};

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

  pinned_cpu = cpu;

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

static size_t percentile_from_samples(const size_t *values, size_t count, double p)
{
  size_t *copy;
  size_t target;
  size_t result;

  if (count == 0)
    return 0;

  copy = malloc(count * sizeof(*copy));
  if (!copy)
    return values[0];

  memcpy(copy, values, count * sizeof(*copy));
  for (size_t i = 1; i < count; ++i) {
    size_t v = copy[i];
    size_t j = i;
    while (j > 0 && copy[j - 1] > v) {
      copy[j] = copy[j - 1];
      --j;
    }
    copy[j] = v;
  }

  target = (size_t)(p * (double)(count - 1));
  result = copy[target];
  free(copy);
  return result;
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

static int build_fr_paths(struct fr_paths *paths)
{
  char exe_path[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  char *slash;

  if (n < 0 || (size_t)n >= sizeof(exe_path))
    return -1;

  exe_path[n] = '\0';
  slash = strrchr(exe_path, '/');
  if (!slash)
    return -1;
  *slash = '\0';

  if (snprintf(paths->detection_dir, sizeof(paths->detection_dir), "%s/..", exe_path) >= (int)sizeof(paths->detection_dir))
    return -1;
  if (snprintf(paths->example_dir, sizeof(paths->example_dir), "%s/example/fr", paths->detection_dir) >= (int)sizeof(paths->example_dir))
    return -1;
  if (snprintf(paths->victim_path, sizeof(paths->victim_path), "%s/victim", paths->example_dir) >= (int)sizeof(paths->victim_path))
    return -1;
  if (snprintf(paths->attack_path, sizeof(paths->attack_path), "%s/F+R", paths->example_dir) >= (int)sizeof(paths->attack_path))
    return -1;

  return 0;
}

static int run_make_target(const char *dir)
{
  pid_t pid = fork();
  int status = 0;

  if (pid < 0)
    return -1;

  if (pid == 0) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    execlp("make", "make", "-C", dir, NULL);
    _exit(127);
  }

  if (waitpid(pid, &status, 0) < 0)
    return -1;

  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static void pin_child_to_cpu(void)
{
  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(pinned_cpu, &set);
  (void)sched_setaffinity(0, sizeof(set), &set);
}

static pid_t spawn_example_process(const char *path)
{
  pid_t pid = fork();

  if (pid < 0)
    return -1;

  if (pid == 0) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    pin_child_to_cpu();
    execl(path, path, NULL);
    _exit(127);
  }

  return pid;
}

static void terminate_process(pid_t pid)
{
  int status = 0;

  if (pid <= 0)
    return;

  kill(pid, SIGTERM);
  for (int i = 0; i < 20; ++i) {
    pid_t rc = waitpid(pid, &status, WNOHANG);
    if (rc == pid)
      return;
    usleep(10000);
  }

  kill(pid, SIGKILL);
  waitpid(pid, &status, 0);
}

static void probe_access_reload_sleep(void)
{
  nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = FR_SLEEP_NSEC}, NULL);
  sched_yield();
}

static size_t measure_detector_round1(void *addr)
{
  asm volatile ("mfence");
  maccess(addr);
  asm volatile ("mfence");
  probe_access_reload_sleep();
  return timed_reload(addr);
}

static size_t measure_detector_round2(void *addr)
{
  flush(addr);
  nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = FR_SLEEP_NSEC}, NULL);
  return timed_reload(addr);
}

static int map_shared_secret(uint8_t **mapped)
{
  int fd;
  uint8_t *addr;

  for (int i = 0; i < 200; ++i) {
    fd = shm_open(FR_SHARED_NAME, O_RDONLY, 0);
    if (fd >= 0) {
      addr = mmap(NULL, SIZE, PROT_READ, MAP_SHARED, fd, 0);
      close(fd);
      if (addr != MAP_FAILED) {
        *mapped = addr;
        return 0;
      }
      return -1;
    }
    usleep(10000);
  }

  return -1;
}

static void collect_detector_samples(uint8_t *shared,
                                     size_t *round1,
                                     size_t *round2,
                                     size_t count)
{
  size_t line_count = SIZE / CACHE_LINE_SIZE;

  for (size_t i = 0; i < count; ++i) {
    uint8_t *addr = shared + (i % line_count) * CACHE_LINE_SIZE;
    round1[i] = measure_detector_round1(addr);
    round2[i] = measure_detector_round2(addr);
  }
}

static void collect_detector_samples_multi(uint8_t *shared,
                                           size_t *round1,
                                           size_t *round2)
{
  for (size_t round = 0; round < FR_GUIDED_ROUNDS; ++round) {
    size_t offset = round * FR_SAMPLE_COUNT_PER_ROUND;
    collect_detector_samples(shared, round1 + offset, round2 + offset, FR_SAMPLE_COUNT_PER_ROUND);
    if (round + 1 < FR_GUIDED_ROUNDS)
      usleep(FR_INTERROUND_USEC);
  }
}

static int refine_thresholds_from_samples(const size_t *benign_r1,
                                          const size_t *benign_r2,
                                          const size_t *attack_r1,
                                          const size_t *attack_r2,
                                          size_t sample_count,
                                          size_t *t_l1_out,
                                          size_t *t_l3_out,
                                          size_t *t_miss_out)
{
  size_t benign_l1_hi = percentile_from_samples(benign_r1, sample_count, 0.95);
  size_t benign_miss_lo = percentile_from_samples(benign_r2, sample_count, 0.20);
  size_t benign_miss_hi = percentile_from_samples(benign_r2, sample_count, 0.95);
  size_t attack_miss_lo = percentile_from_samples(attack_r1, sample_count, 0.20);
  size_t attack_miss_hi = percentile_from_samples(attack_r1, sample_count, 0.95);
  size_t attack_reload_hi = percentile_from_samples(attack_r2, sample_count, 0.95);
  size_t miss_floor = MIN(benign_miss_lo, attack_miss_lo);
  size_t miss_ceiling = MAX(benign_miss_hi, MAX(attack_miss_hi, attack_reload_hi));
  size_t t_l1;
  size_t t_l3;
  size_t t_miss;

  if (sample_count == 0)
    return -1;

  t_l1 = round_up_to(benign_l1_hi + 2 * BIN_SIZE, T_L1_ROUND_TO);
  t_l3 = round_up_to(MAX(t_l1 + FR_L3_GAP_MIN, miss_floor > FR_L3_GAP_MIN ? miss_floor - FR_L3_GAP_MIN : miss_floor),
                     T_L3_ROUND_TO);
  t_miss = round_up_to(MAX(t_l3 + FR_MISS_GAP_MIN, miss_ceiling + FR_MISS_GAP_MIN), T_MISS_ROUND_TO);

  *t_l1_out = t_l1;
  *t_l3_out = t_l3;
  *t_miss_out = t_miss;
  return 0;
}

static int run_fr_guided_calibration(size_t *t_l1_out,
                                     size_t *t_l3_out,
                                     size_t *t_miss_out)
{
  struct fr_paths paths;
  size_t t_l1_passes[FR_REFINEMENT_PASSES];
  size_t t_l3_passes[FR_REFINEMENT_PASSES];
  size_t t_miss_passes[FR_REFINEMENT_PASSES];
  size_t pass_count = 0;
  int rc = -1;

  if (build_fr_paths(&paths) != 0)
    return -1;
  if (run_make_target(paths.example_dir) != 0)
    return -1;

  for (size_t pass = 0; pass < FR_REFINEMENT_PASSES; ++pass) {
    uint8_t *shared = NULL;
    pid_t victim_pid = -1;
    pid_t attack_pid = -1;
    size_t benign_r1[FR_SAMPLE_COUNT];
    size_t benign_r2[FR_SAMPLE_COUNT];
    size_t attack_r1[FR_SAMPLE_COUNT];
    size_t attack_r2[FR_SAMPLE_COUNT];
    size_t t_l1_pass;
    size_t t_l3_pass;
    size_t t_miss_pass;

    victim_pid = spawn_example_process(paths.victim_path);
    if (victim_pid < 0)
      goto pass_cleanup;
    usleep(FR_SETTLE_USEC);

    if (map_shared_secret(&shared) != 0)
      goto pass_cleanup;

    collect_detector_samples_multi(shared, benign_r1, benign_r2);

    attack_pid = spawn_example_process(paths.attack_path);
    if (attack_pid < 0)
      goto pass_cleanup;
    usleep(FR_SETTLE_USEC);

    collect_detector_samples_multi(shared, attack_r1, attack_r2);

    if (refine_thresholds_from_samples(benign_r1, benign_r2,
                                       attack_r1, attack_r2,
                                       FR_SAMPLE_COUNT,
                                       &t_l1_pass, &t_l3_pass, &t_miss_pass) == 0) {
      t_l1_passes[pass_count] = t_l1_pass;
      t_l3_passes[pass_count] = t_l3_pass;
      t_miss_passes[pass_count] = t_miss_pass;
      ++pass_count;
    }

pass_cleanup:
    if (shared)
      munmap(shared, SIZE);
    terminate_process(attack_pid);
    terminate_process(victim_pid);
    shm_unlink(FR_SHARED_NAME);
    if (pass + 1 < FR_REFINEMENT_PASSES)
      usleep(FR_INTERPASS_USEC);
  }

  if (pass_count == 0)
    return -1;

  *t_l1_out = median_of(t_l1_passes, pass_count);
  *t_l3_out = median_of(t_l3_passes, pass_count);
  *t_miss_out = median_of(t_miss_passes, pass_count);
  rc = 0;

  return rc;
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
  size_t raw_T_L1;
  size_t raw_T_L3;
  size_t raw_T_MISS;
  size_t final_T_L1;
  size_t final_T_L3;
  size_t final_T_MISS;
  char constants_path[PATH_MAX];
  int used_fr_guided = 0;

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

  raw_T_L1 = median_of(t_l1_rounds, CALIBRATION_ROUNDS);
  raw_T_L3 = median_of(t_l3_rounds, CALIBRATION_ROUNDS);
  raw_T_MISS = median_of(t_miss_rounds, CALIBRATION_ROUNDS);

  if (raw_T_L3 <= raw_T_L1)
    raw_T_L3 = raw_T_L1 + BIN_SIZE;
  if (raw_T_MISS <= raw_T_L3)
    raw_T_MISS = raw_T_L3 + BIN_SIZE;

  raw_T_L1 = round_up_to(raw_T_L1, T_L1_ROUND_TO);
  raw_T_L3 = round_up_to(MAX(raw_T_L3, raw_T_L1 + BIN_SIZE), T_L3_ROUND_TO);
  raw_T_MISS = round_up_to(MAX(raw_T_MISS, raw_T_L3 + BIN_SIZE), T_MISS_ROUND_TO);

  final_T_L1 = raw_T_L1;
  final_T_L3 = raw_T_L3;
  final_T_MISS = raw_T_MISS;

  if (run_fr_guided_calibration(&final_T_L1, &final_T_L3, &final_T_MISS) == 0)
    used_fr_guided = 1;

  printf("\n=== 4-bucket thresholds ===\n");
  printf("Measured as delta = rdtsc(); maccess(addr); rdtsc() - delta.\n");
  printf("Calibration is pinned to one CPU and reports the median of %d rounds.\n",
         CALIBRATION_ROUNDS);
  if (used_fr_guided)
    printf("Final thresholds were refined using %d medianed example/fr sessions, each with %d aggregated rounds.\n",
           FR_REFINEMENT_PASSES, FR_GUIDED_ROUNDS);
  else
    printf("Thresholds are widened from that machine's measured fast-hit and miss spread, without example/fr refinement.\n");

  printf("\nRaw thresholds:\n");
  printf("  T_L1   = %zu\n", raw_T_L1);
  printf("  T_L3   = %zu\n", raw_T_L3);
  printf("  T_MISS = %zu\n", raw_T_MISS);

  printf("\nSuggested thresholds (FR-example-refined):\n");
  printf("  T_L1   = %zu\n", final_T_L1);
  printf("  T_L3   = %zu\n", final_T_L3);
  printf("  T_MISS = %zu\n", final_T_MISS);

  if (build_constants_path(constants_path, sizeof(constants_path)) != 0 ||
      write_updated_constants(constants_path, final_T_L1, final_T_L3, final_T_MISS) != 0) {
    fprintf(stderr, "\nFailed to update constants.h automatically.\n");
    return 1;
  }

  printf("\nUpdated %s\n", constants_path);

  return 0;
}
