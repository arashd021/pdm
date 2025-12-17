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

#define NUM_FEATURES 8
#define WINDOW_SIZE 16
#define START_ADDR 0x7ffff7fcf000
#define TARGET_OFFSET  20
#define SIZE 1024
#define PAGE_SIZE 4096
#define CACHE_LINE_SIZE 64
#define NUM_CACHE_LINES (SIZE / CACHE_LINE_SIZE)
#define BATCH_SIZE 8
#define PROBE_ROUND_SIZE SIZE/64

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
    uintptr_t start_addr = get_shared_secret_address(getpid());
    printf("Start Address Extracted by PDM: 0x%lx\n", start_addr);
    size_t total_size = SIZE;
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
            asm volatile("mfence");
            asm volatile("movq (%0), %%rax\n" : : "r"(ptr) : "rax");
            asm volatile("mfence");
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 1000000}, NULL);
            asm volatile("mfence");
            size_t timeDelta = __rdtsc();
            asm volatile("mfence");
            asm volatile("movq (%0), %%rax\n" : : "r"(ptr) : "rax");
            asm volatile("mfence");
            size_t delta = __rdtsc() - timeDelta;
            asm volatile("mfence");

            // printf("%zu\n", delta);

            if (delta < 100)
                l1_hit++;
            else if (delta < 230)
                l3_hit++;
            else if (delta < 450)
                miss++;
            else
                bigmiss++;
        }

        // ---- Second Round: FLUSH + RELOAD ----
        for (size_t i = 0; i < addresses_per_batch; i++) {
            uint8_t *ptr = (uint8_t*)(start_addr + batch_offset + i * CACHE_LINE_SIZE);
            
            asm volatile("mfence");
            asm volatile("clflush (%0)" :: "r"(ptr));
            asm volatile("mfence");
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 1000000}, NULL);
            asm volatile("mfence");
            size_t timeDelta = __rdtsc();
            asm volatile("mfence");
            asm volatile("movq (%0), %%rax\n" : : "r"(ptr) : "rax");
            asm volatile("mfence");
            size_t delta = __rdtsc() - timeDelta;
            asm volatile("mfence");

            // printf("%zu\n", delta);

            if (delta < 100)
                l1_hit2++;
            else if (delta < 230)
                l3_hit2++;
            else if (delta < 450)
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

/* --------------------------------------------------------------------------- */
/*  libc interposition basics (needed by constructors below)                   */
typedef int (*main_t)(int,char**,char**);
typedef int (*libc_start_main_t)(main_t,int,char**,void(*)(void),
                                 void(*)(void),void(*)(void),void*);

/* one real definition – the linker needs this symbol */
static main_t            real_prog_main  = NULL;
static libc_start_main_t real_start_main = NULL;

/* forward decl so constructors can start the thread */
static void *PDM_probe_thread(void *arg);


/* --------------------------------------------------------------------------- */
/*  1. fork-safety: clear global state in a brand-new child                     */
static void atfork_prepare(void)            { pthread_mutex_lock(&ort_big_lock); }
static void atfork_parent(void)             { pthread_mutex_unlock(&ort_big_lock); }
static void atfork_child(void)
{
    if (session && g_ort)        g_ort->ReleaseSession(session);
    if (g_input_tensor && g_ort) g_ort->ReleaseValue(g_input_tensor);
    if (g_memory_info && g_ort)  g_ort->ReleaseMemoryInfo(g_memory_info);

    free(input_name);  input_name  = NULL;
    free(output_name); output_name = NULL;

    session        = NULL;
    g_input_tensor = NULL;
    g_memory_info  = NULL;
    env            = NULL;                    /* force rebuild on demand */
    ml_once        = (pthread_once_t)PTHREAD_ONCE_INIT;

    pthread_mutex_unlock(&ort_big_lock);
}

static int  PDM_i_am_root = 0;
static int  probe_created   = 0; 

__attribute__((constructor))
static void register_fork_handlers(void)
{
    pthread_atfork(atfork_prepare, atfork_parent, atfork_child);
    if (getenv("PDM_ROOT") == NULL) {
        setenv("PDM_ROOT", "1", 1);   /* inherit to children        */
        PDM_i_am_root = 1;
    }
}

__attribute__((constructor))
static void PDM_runtime_init(void)
{
    /* If real_start_main is non-NULL, our __libc_start_main was already
     * called (LD_PRELOAD path). In that case wrapped_main will take care
     * of starting the probe thread – do nothing here.
     */
    if (real_start_main != NULL)
        return;

    /* Runtime injection path: we got dlopen()'d / injected into an already
     * running process. There will be no future call to __libc_start_main,
     * so we must start the probe thread here.
     */
    if (!PDM_i_am_root) {
        /* register_fork_handlers may already have set this; if not,
         * we make this process the root for PDM.
         */
        PDM_i_am_root = 1;
    }

    if (!probe_created++) {
        if (!pthread_create(&probe_tid, NULL, PDM_probe_thread, NULL)) {
            probe_alive = 1;
        } else {
            perror("[PDM] pthread_create (runtime)");
        }
    }
}


/* --------------------------------------------------------------------------- */
/*  2. background probe thread                                                 */
static void *PDM_probe_thread(void *arg)
{
    (void)arg;
    // fprintf(stderr, "[PDM] probe thread started (pid=%d)\n", getpid());
    PDM_Probing(NULL);
    return NULL;          /* never reached */
}


/*  We replace the program’s main with this wrapper:                           *
 *    – creates the probe thread exactly once, *before* user code starts      *
 *    – then tail-calls the real program main                                  */
static int wrapped_main(int argc, char **argv, char **envp)
{
    if (PDM_i_am_root && !probe_created++) {                        /* first call in *root*   */
        pthread_t tid;
        if (!pthread_create(&probe_tid, NULL, PDM_probe_thread, NULL)) {
            probe_alive = 1;
        } else {
            perror("[PDM] pthread_create");
        }
    }

    extern main_t real_prog_main;                  /* assigned below */
    return real_prog_main(argc, argv, envp);
}


__attribute__((visibility("default")))
int __libc_start_main(main_t     main,
                      int        argc,
                      char     **ubp_av,
                      void (*init)(void),
                      void (*fini)(void),
                      void (*rtld_fini)(void),
                      void     *stack_end)
{
    if (!real_start_main) {
        real_start_main = (libc_start_main_t)dlsym(RTLD_NEXT,
                                                   "__libc_start_main");
        if (!real_start_main) {
            fputs("[PDM] dlsym failed for __libc_start_main\n", stderr);
            _exit(1);
        }
    }

    /* remember original program main so wrapper can tail-call it */
    extern main_t real_prog_main;
    real_prog_main = main;

    /* hand control back to glibc, substituting our wrapper */
    return real_start_main(wrapped_main, argc, ubp_av,
                           init, fini, rtld_fini, stack_end);
}

/* --------------------------------------------------------------------------- */
/*  3. tidy-up                                                                 */
__attribute__((destructor))
static void PDM_cleanup(void)
{
    if (probe_alive) {
        atomic_store_explicit(&PDM_stop, 1, memory_order_relaxed);
        pthread_join(probe_tid, NULL);          /* wait until it returns       */
        probe_alive = 0;
    }
    if (session && g_ort)        g_ort->ReleaseSession(session);
    if (g_input_tensor && g_ort) g_ort->ReleaseValue(g_input_tensor);
    if (g_memory_info && g_ort)  g_ort->ReleaseMemoryInfo(g_memory_info);

    free(input_name);
    free(output_name);

    if (env && g_ort)            g_ort->ReleaseEnv(env);
}
