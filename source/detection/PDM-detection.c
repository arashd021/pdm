// gcc -O3 -march=native -fno-builtin -fno-jump-tables -fPIC -shared -o PDM-detection.so PDM-detection.c -I$HOME/onnxruntime-linux-x64-1.22.0/include -L$HOME/onnxruntime-linux-x64-1.22.0/lib -lonnxruntime -lpthread -fno-stack-protector -fno-builtin -fno-jump-tables -fno-common -Wl,-rpath,$HOME/onnxruntime-linux-x64-1.22.0/lib

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
#include <stdbool.h>
#include <onnxruntime_c_api.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <signal.h>
#include <setjmp.h>

// ---- Address selection mode ----
// Uncomment exactly ONE of these
#define USE_FIXED_START_ADDR
// #define USE_PROC_MAPS

#define START_ADDR 0x7ffff6fdf000
#define SIZE 3072

#define NUM_FEATURES 8
#define WINDOW_SIZE 16
#define TARGET_OFFSET  20
#define PAGE_SIZE 4096
#define CACHE_LINE_SIZE 64
#define NUM_CACHE_LINES (SIZE / CACHE_LINE_SIZE)
#define BATCH_SIZE 8
#define PROBE_ROUND_SIZE SIZE/64

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


// -------------------- ONNX Runtime Integration -------------------- //
const OrtApi* g_ort = NULL;
OrtEnv* env = NULL;
OrtSession* session = NULL;
char* input_name = NULL;
char* output_name = NULL;
// Global variables for persistent ONNX input resources.
static OrtMemoryInfo* g_memory_info = NULL;
static float g_input_buffer[NUM_FEATURES];   // Persistent input buffer
static OrtValue* g_input_tensor = NULL;        // Persistent input tensor


static atomic_int  PDM_stop = 0;     /* 0 = keep running, 1 = exit soon      */
static pthread_t   probe_tid;           /* main keeps the thread id so we can   */
static int         probe_alive = 0;     /* join it later in the destructor      */

static int                ort_crashed      = 0;   /* sticky after first SEGV */

static __thread sigjmp_buf *tls_jmpbuf = NULL;   /* NULL → not in ORT   */

static void ort_sig_handler(int sig, siginfo_t *si, void *ctx)
{
    if (tls_jmpbuf) {                 /* fault during ONNX inference */
        siglongjmp(*tls_jmpbuf, 1);   /* unwind to run_inference_safe */
    }

    /* fault somewhere else: restore default and re-raise */
    struct sigaction sa = { .sa_handler = SIG_DFL };
    sigaction(sig, &sa, NULL);
    raise(sig);
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




/* install once per process */
static void ort_seatbelt_init(void)
{
    struct sigaction sa = {0};
    sa.sa_sigaction = ort_sig_handler;
    sa.sa_flags     = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS , &sa, NULL);
}

static uintptr_t get_binary_base(void)
{
    Dl_info info;
    /* any symbol from the main executable works; use this function itself */
    if (dladdr((void *)get_binary_base, &info) && info.dli_fbase)
        return (uintptr_t)info.dli_fbase;

    /* Fallback: parse /proc/self/maps */
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[256];
    while (fgets(line, sizeof line, fp)) {
        if (strstr(line, " r-xp ") && !strchr(line, '/')) {   /* anonymous => main */
            uintptr_t start;
            if (sscanf(line, "%lx-%*lx", &start) == 1) {
                fclose(fp);
                return start;
            }
        }
    }
    fclose(fp);
    return 0;
}

void print_ort_error(const char* msg, OrtStatus* status) {
    // fprintf(stderr, "[PDM] ORT-error: %s: %s\n",
    //         msg, g_ort->GetErrorMessage(status ? status : NULL));
    if (status) g_ort->ReleaseStatus(status);

    ort_crashed = 1;

}

// Load the ONNX model (single thread)
OrtSession* load_model(OrtEnv* env, const char* model_path) {
    OrtSessionOptions* session_options = NULL;
    OrtStatus* status = g_ort->CreateSessionOptions(&session_options);

    if (status != NULL) {                 /* give up gracefully      */
        print_ort_error("CreateSessionOptions", status);
        return NULL;
    }

    // Set graph optimization level
    status = g_ort->SetSessionGraphOptimizationLevel(session_options, ORT_DISABLE_ALL);
    if (status != NULL) {
        print_ort_error("Failed to set session graph optimization level", status);
        g_ort->ReleaseSessionOptions(session_options);
        return NULL;
    }

    // Set the number of threads to 1
    status = g_ort->SetIntraOpNumThreads(session_options, 1);
    if (status != NULL) {
        print_ort_error("Failed to set intra op num threads", status);
        g_ort->ReleaseSessionOptions(session_options);
        return NULL;
    }

    status = g_ort->SetInterOpNumThreads(session_options, 1);
    if (status != NULL) {
        print_ort_error("Failed to set inter op num threads", status);
        g_ort->ReleaseSessionOptions(session_options);
        return NULL;
    }

    OrtSession* session_local = NULL;
    status = g_ort->CreateSession(env, model_path, session_options, &session_local);
    g_ort->ReleaseSessionOptions(session_options);

    if (status != NULL) {
        print_ort_error("Failed to create ONNX Runtime session", status);
        return NULL;
    }

    return session_local;
}

// Function to get input and output names
/* helper: abort on any non-NULL OrtStatus* */
static inline void ORT_CHECK(OrtStatus *st, const char *msg)
{
    if (st) {
        // fprintf(stderr, "%s: %s\n", msg, g_ort->GetErrorMessage(st));
        g_ort->ReleaseStatus(st);
        _exit(1);
    }
}

void get_model_io_names(OrtSession *session,
                        char **input_name_ptr,
                        char **output_name_ptr)
{
    /* 1) get default allocator */
    OrtAllocator *alloc = NULL;
    ORT_CHECK(g_ort->GetAllocatorWithDefaultOptions(&alloc),
              "GetAllocatorWithDefaultOptions");

    /* 2) fetch raw names (owned by ORT allocator) */
    char *tmp_in  = NULL;
    char *tmp_out = NULL;
    ORT_CHECK(g_ort->SessionGetInputName (session, 0, alloc, &tmp_in),
              "SessionGetInputName");
    ORT_CHECK(g_ort->SessionGetOutputName(session, 0, alloc, &tmp_out),
              "SessionGetOutputName");

    /* 3) take private copies that live as long as the session */
    *input_name_ptr  = strdup(tmp_in);
    *output_name_ptr = strdup(tmp_out);

    /* 4) return original buffers to ORT allocator (check status!) */
    ORT_CHECK(g_ort->AllocatorFree(alloc, tmp_in),  "AllocatorFree input name");
    ORT_CHECK(g_ort->AllocatorFree(alloc, tmp_out), "AllocatorFree output name");
}


void initialize_inference_resources() {
    // Create the CPU memory info once.
    OrtStatus* status = g_ort->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &g_memory_info);
    if (status != NULL) {
        print_ort_error("Failed to create CPU memory info", status);
        exit(EXIT_FAILURE);
    }

    // Define the input tensor shape (for example: [1, 1, NUM_FEATURES]).
    int64_t input_shape[3] = {1, 1, NUM_FEATURES};

    // Create the persistent input tensor using the preallocated g_input_buffer.
    status = g_ort->CreateTensorWithDataAsOrtValue(
        g_memory_info,
        g_input_buffer,
        NUM_FEATURES * sizeof(float),  // Size in bytes
        input_shape,
        3, // Rank
        ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
        &g_input_tensor
    );
    if (status != NULL) {
        print_ort_error("Failed to create persistent input tensor", status);
        exit(EXIT_FAILURE);
    }
}

// Function to run inference
float run_inference(OrtSession* session, const char* input_name, const char* output_name, float* input_tensor_values) {
    // Update the persistent input buffer with the new input data.
    memcpy(g_input_buffer, input_tensor_values, NUM_FEATURES * sizeof(float));

    // Prepare input and output names.
    const char* input_names[] = { input_name };
    const char* output_names[] = { output_name };
    size_t num_inputs = 1;
    size_t num_outputs = 1;

    // Run inference using the pre-allocated input tensor.
    OrtValue* output_tensor = NULL;
    OrtStatus* status = g_ort->Run(
        session,
        NULL, // run options
        input_names,
        (const OrtValue* const*)&g_input_tensor,
        num_inputs,
        output_names,
        num_outputs,
        &output_tensor
    );
    if (status != NULL) {
        // print_ort_error("Failed to run inference", status);
        return -1.0f;
        // exit(EXIT_FAILURE);
    }

    // Get the output tensor data.
    float* float_array;
    status = g_ort->GetTensorMutableData(output_tensor, (void**)&float_array);
    if (status != NULL) {
        print_ort_error("Failed to get output tensor data", status);
        g_ort->ReleaseValue(output_tensor);
        exit(EXIT_FAILURE);
    }

    float result = float_array[0];
    g_ort->ReleaseValue(output_tensor);
    return result;
}



// Function to print ratios
void print_ratios(const char* timeStr, float l1hitratio, float l3hitratio, float missratio, float bigmissratio, 
                 float l1hitratio2, float l3hitratio2, float missratio2, float bigmissratio2, size_t batch_offset,float model_output) {
    printf("%s", timeStr);
    printf(" l1hit: %6.2f ** l3hit: %6.2f  ** miss: %6.2f ** bigmiss: %6.2f", l1hitratio, l3hitratio, missratio, bigmissratio);
    printf(" ===== ");
    printf(" l1hit2: %6.2f ** l3hit2: %6.2f ** miss2: %6.2f ** bigmiss2: %6.2f", l1hitratio2, l3hitratio2, missratio2, bigmissratio2);
    printf(" | Model Output: %f", model_output);
    printf(" ** batch_offset: %zu", batch_offset);
    printf("\n");
}


/* ---------- 1.  Big process-wide lock protecting every call into ORT ------------ */
static pthread_mutex_t ort_big_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------- 2.  Serialised wrapper around the original run_inference() ---------- */
static inline float
run_inference_safe(OrtSession *sess,
                   const char *in_name,
                   const char *out_name,
                   float       *input)
{
    /* if ORT has crashed once, never call it again in this process      */
    if (ort_crashed || !session) return -1.0f;

    sigjmp_buf  jmp;                       /* automatic → thread-local */
    float       rv  = -1.0f;

    pthread_mutex_lock(&ort_big_lock);

    tls_jmpbuf = &jmp;                     /* mark “inside ORT”        */
    if (sigsetjmp(jmp, 1) == 0) {          /* first time               */
        rv = run_inference(session, in_name, out_name, input);
    } else {                               /* came from handler        */
        fprintf(stderr,
          "[PDM] ONNX crashed – disabled for pid %d\n", getpid());
        ort_crashed = 1;
    }
    tls_jmpbuf = NULL;                     /* leave protected region   */

    pthread_mutex_unlock(&ort_big_lock);
    return rv;
}



/* ---------- 3.  Lazy one-time ML initialisation per *process* ------------------- */
static pthread_once_t ml_once = PTHREAD_ONCE_INIT;

static void build_ml_once(void)
{
    ort_seatbelt_init();
    g_ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);
    
    if (!env) {
        OrtStatus *st = g_ort->CreateEnv(ORT_LOGGING_LEVEL_WARNING,
                                         "PDM", &env);
        if (st) {
            // fprintf(stderr, "ORT env error: %s\n",g_ort->GetErrorMessage(st));
            g_ort->ReleaseStatus(st);
            _exit(1);
        }
    }
    // Update if needed; absolute path only
    const char *model = "/home/vagrant/PDM/source/detection/PDM-model.onnx";

    session = load_model(env, model);
    if (!session) {              /* give up */
        ort_crashed = 1;         /* block future calls */
        return;
    }

    // fprintf(stderr, "[PDM] ONNX-Runtime %s loaded\n",OrtGetApiBase()->GetVersionString());

    get_model_io_names(session, &input_name, &output_name);
    initialize_inference_resources();
}

// Probing Code
void* PDM_Probing(void* arg) {
    // uintptr_t base = get_binary_base();
    // if (!base) {
    //     // fprintf(stderr, "PDM: could not locate binary base address\n");
    //     pthread_exit(NULL);
    // }
    // uintptr_t start_addr = base + TARGET_OFFSET;
    // uintptr_t start_addr = START_ADDR;

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

    size_t batch_offset = 0;
    size_t addresses_per_batch = BATCH_SIZE;

    // Counters for round 1 (ACCESS+RELOAD)
    long long l1_hit = 0, l3_hit = 0, miss = 0, bigmiss = 0;
    // Counters for round 2 (FLUSH+RELOAD)
    long long l1_hit2 = 0, l3_hit2 = 0, miss2 = 0, bigmiss2 = 0;

    while (!atomic_load_explicit(&PDM_stop, memory_order_relaxed)) {
        // ---- First Round: ACCESS + RELOAD ----
        for (size_t i = 0; i < addresses_per_batch; i++) {
            uint8_t *ptr = (uint8_t*)(start_addr + batch_offset + i * CACHE_LINE_SIZE);
            asm volatile ("mfence");
            maccess(ptr);
            asm volatile ("mfence");
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 300000}, NULL);
            sched_yield();
            size_t timeDelta = rdtsc();
            maccess(ptr);
            size_t delta = rdtsc() -  timeDelta;

            // printf("%zu\n", delta);

            // adjust threshold
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
            uint8_t *ptr = (uint8_t*)(start_addr + batch_offset + i * CACHE_LINE_SIZE);
            
            flush(ptr);
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 300000}, NULL);
            size_t time = rdtsc();
            maccess(ptr);
            size_t delta = rdtsc() - time;

            // printf("%zu\n", delta);

            // adjust threshold
            if (delta < 500)
                l1_hit2++;
            else if (delta < 700)
                l3_hit2++;
            else if (delta < 1000)
                miss2++;
            else
                bigmiss2++;
        }

        // ---- Compute ratios based on the current batch ----
        double l1hitratio    = (double)l1_hit    / addresses_per_batch * 100;
        double l3hitratio    = (double)l3_hit    / addresses_per_batch * 100;
        double missratio     = (double)miss      / addresses_per_batch * 100;
        double bigmissratio  = (double)bigmiss   / addresses_per_batch * 100;
        double l1hitratio2   = (double)l1_hit2   / addresses_per_batch * 100;
        double l3hitratio2   = (double)l3_hit2   / addresses_per_batch * 100;
        double missratio2    = (double)miss2     / addresses_per_batch * 100;
        double bigmissratio2 = (double)bigmiss2  / addresses_per_batch * 100;


        // **Assemble input data with the number of features**
        float input_data[NUM_FEATURES] = {0};
        float features[NUM_FEATURES] = {
            (float)l1hitratio,
            (float)l3hitratio,
            (float)missratio,
            (float)bigmissratio,
            (float)l1hitratio2,
            (float)l3hitratio2,
            (float)missratio2,
            (float)bigmissratio2
        };

        for (int f = 0; f < NUM_FEATURES; f++) {
            input_data[f] = features[f];
        }

        float model_output=0;
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        // Only activate ML when necessary
        if (!atomic_load_explicit(&PDM_stop, memory_order_relaxed) && (l1hitratio2 > 25 || missratio > 25)) {
            pthread_once(&ml_once, build_ml_once);
            model_output = run_inference_safe(session, input_name, output_name, input_data);
        }
        // pthread_once(&ml_once, build_ml_once);
        // model_output = run_inference_safe(session, input_name, output_name, input_data);
        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        // printf("Inference time: %f ms\n", elapsed * 1000);

        char timeStr[20];
        struct timeval tv;
        time_t now;
        gettimeofday(&tv, NULL);
        now = tv.tv_sec;
        struct tm *tm_now = localtime(&now);
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", tm_now);
        snprintf(timeStr + 8, sizeof(timeStr) - 8, ".%03u", (unsigned)((tv.tv_usec / 1000) % 1000));


        // Print ratios and model output
        print_ratios(timeStr, (float)l1hitratio, (float)l3hitratio, (float)missratio, (float)bigmissratio, (float)l1hitratio2, (float)l3hitratio2, (float)missratio2, (float)bigmissratio2, batch_offset, model_output);
        
        // Reset counters for the next batch
        l1_hit = l3_hit = miss = bigmiss = 0;
        l1_hit2 = l3_hit2 = miss2 = bigmiss2 = 0;

        // Update batch offset: move to the next batch
        batch_offset += addresses_per_batch * CACHE_LINE_SIZE;
        if (batch_offset >= total_size)
            batch_offset = 0;
    }
    return NULL;
}

// -------------------- Initialization -------------------- //
__attribute__((constructor)) __attribute__((visibility("default")))
void init_library() {
    int N = 1;
    pthread_t tids[1];
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

// -------------------- End of Program -------------------- //
