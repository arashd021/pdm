#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <unistd.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <sys/ucontext.h>
#include <limits.h>
#include <pthread.h>
#include <uthash.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/random.h>

#define ALT_STACK_SZ   (64 * 1024)
#define PAGE_SZ  4096
#define PATCH_REL32_LEN 5
#define PATCH_ABS_R11_LEN 13   /* 49 BB imm64 ; 41 FF E3 */

#ifdef DEBUG
# include <sys/syscall.h>
# define TID   ((pid_t)syscall(SYS_gettid))
# define DBG(fmt, ...) \
    fprintf(stderr, "[%d:%d] " fmt "\n", (int)getpid(), (int)TID, \
            ##__VA_ARGS__)
#else
# define DBG(...)  ((void)0)
#endif


#define ABORT(fmt, ...)  do{ \
        DBG("FATAL: " fmt, ##__VA_ARGS__);  \
        raise(SIGABRT); }while(0)


/* -------------------------------------------------------- */
/* ---------------------  Global Vars --------------------- */
/* -------------------------------------------------------- */

/* Protected Address in the victim */
static char  *secret;
static size_t secret_len;

static char  *encrypted_secret = NULL;   /* shadow – allocated on demand */
static char  *secret_mask_page = NULL;   /* mask  – allocated on demand  */
extern  bool  disable_secret;            /* set by victim                */

/* exact logical secret object inside the guarded page(s) */
static char  *masked_secret      = NULL;   /* exact addr passed to install_guard() */
static size_t masked_secret_len  = 0;      /* exact len  passed to install_guard() */

static int patch_counter = 0;
static csh cs;      /* Capstone handle (global) */
static int64_t SHADOW_DELTA;
static int64_t MASK_DELTA;          /*   secret_mask_page – encrypted_secret  */
/* -------------------------------------------------------- */

#ifndef PDM_MASKING
#define PDM_MASKING 0
#endif

static void dump(const char *lbl, const uint8_t *p, size_t n)
{
    #ifdef DEBUG
        /* keep the same PID/TID prefix used by DBG() */
        fprintf(stderr, "[%d:%d] %s @%p :", (int)getpid(), (int)TID, lbl, (void *)p);
        for (size_t i = 0; i < n; i++)
            fprintf(stderr, " %02x", p[i]);
        fputc('\n', stderr);
    #else
        (void)lbl; (void)p; (void)n;   /* silence -O2 -Wunused warnings */
    #endif
}

#if PDM_MASKING
static __thread uint8_t tls_mask_prng_state[16];
static __thread uint8_t tls_mask_prng_round_key[16];
static __thread int     tls_mask_prng_ready = 0;

static void fill_random(void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = getrandom(p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("getrandom");
            exit(1);
        }
        if (n == 0) {
            fprintf(stderr, "getrandom returned 0\n");
            exit(1);
        }
        p   += (size_t)n;
        len -= (size_t)n;
    }
}

/* setup-time seeding only; NOT used from emitted trampolines */
static void pdm_mask_prng_init_tls(void)
{
    if (tls_mask_prng_ready) return;

    fill_random(tls_mask_prng_state, sizeof(tls_mask_prng_state));
    fill_random(tls_mask_prng_round_key, sizeof(tls_mask_prng_round_key));

    tls_mask_prng_ready = 1;

    dump("tls_mask_prng_state INIT", tls_mask_prng_state, sizeof(tls_mask_prng_state));
    dump("tls_mask_prng_round_key INIT", tls_mask_prng_round_key, sizeof(tls_mask_prng_round_key));
}

/* setup-time bulk randomness only; refreshes are done inline in trampolines */
static void pdm_mask_prng_bytes(void *out, size_t n)
{
    pdm_mask_prng_init_tls();

    fill_random(out, n);
}
#else
static inline void pdm_mask_prng_init_tls(void) {}
static inline void pdm_mask_prng_bytes(void *out, size_t n) { (void)out; (void)n; }
#endif

__attribute__((visibility("default")))
void install_guard(void *addr, size_t len)
{
    if (!addr || len == 0) return;

    masked_secret     = (char *)addr;
    masked_secret_len = len;
    
    /* ── 1. round down to page boundary, round up the length ───────── */
    const size_t  PAGE = (size_t)sysconf(_SC_PAGESIZE);    /* 4096 */
    uintptr_t base     = (uintptr_t)addr & ~(PAGE - 1);    /* page-aligned */
    size_t    offset   = (uintptr_t)addr - base;           /* inside page  */
    size_t    plen     = (len + offset + PAGE - 1) & ~(PAGE - 1);
    

    secret      = (char *)base;
    secret_len  = plen;
    
    DBG("guard page   = [%p .. %p) len=%zu",
        (void *)secret, (void *)(secret + secret_len), secret_len);
    DBG("masked object= [%p .. %p) len=%zu",
        (void *)masked_secret, (void *)(masked_secret + masked_secret_len), masked_secret_len);

    /* ── 2. allocate mask + shadow exactly “plen” bytes  ───────────── */
    secret_mask_page = mmap(NULL, plen, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    encrypted_secret = mmap(NULL, plen, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (secret_mask_page == MAP_FAILED || encrypted_secret == MAP_FAILED)
        perror("mmap"), exit(1);
    SHADOW_DELTA = (int64_t)encrypted_secret - (int64_t)secret;
    MASK_DELTA   = (int64_t)secret_mask_page - (int64_t)encrypted_secret;

    /*
     * Whole guarded page(s): plain mirror into encrypted_secret, zero masks.
     * Exact logical object only: apply masking.
     */
    memset(secret_mask_page, 0, plen);
    memcpy(encrypted_secret, secret, plen);

    #if PDM_MASKING
        pdm_mask_prng_init_tls();

        size_t obj_off = (size_t)((uintptr_t)masked_secret - (uintptr_t)secret);

        pdm_mask_prng_bytes(secret_mask_page + obj_off, masked_secret_len);
        dump("secret_mask_page INIT", (const uint8_t *)secret_mask_page, 64);

        for (size_t i = 0; i < masked_secret_len; i++) {
            const size_t idx  = obj_off + i;
            const uint8_t plain = ((const uint8_t *)secret)[idx];
            const uint8_t mask  = ((const uint8_t *)secret_mask_page)[idx];
            encrypted_secret[idx] = (char)(plain ^ mask);
        }
    #endif

    /* victim memory always reflects the shadow bytes */
    // memcpy(secret, encrypted_secret, plen);

    /* original secret region wiped for security */
    memset(secret, 0, plen);

    /* Print masked secret */
    printf("[victim] secret AFTER guarding (wiped):");
    for (size_t i = 0; i < len; i++) {
        printf(" %02x", ((uint8_t *)secret)[i]);
    }
    printf("\n");

    printf("[victim] Encrypted Shadow AFTER guarding:");
    for (size_t i = 0; i < len; i++) {
        printf(" %02x", ((uint8_t *)encrypted_secret)[i]);
    }
    printf("\n");

    /* ── 3. mprotect-protect the *page-aligned* range ───────────────── */
    if (disable_secret) {  /* argv[1] == 2 → "Protect Key" mode */
        if (mprotect(secret, plen, PROT_NONE) != 0) {
            perror("mprotect(PROT_NONE)");
            exit(1);
        }
    }
}

/* cached patch info: rip -> trampoline pointer */
typedef struct {
    uint64_t orig_pc;   /* original instruction address inside stolen range */
    uint64_t tramp_pc;  /* corresponding address inside trampoline */
} stolen_entry_t;

typedef struct {
    uint64_t rip;
    uint8_t  orig_len;
    uint8_t *tramp;

    stolen_entry_t *entries;
    size_t          entry_count;
    size_t          entry_cap;

    UT_hash_handle hh;
} patch_t;

static patch_t *patches = NULL;

static void patch_add_entry(patch_t *p, uint64_t orig_pc, uint64_t tramp_pc)
{
    if (!p) ABORT("patch_add_entry: p == NULL");

    if (p->entry_count == p->entry_cap) {
        size_t new_cap = (p->entry_cap == 0) ? 8 : (p->entry_cap * 2);
        stolen_entry_t *new_entries =
            (stolen_entry_t *)realloc(p->entries, new_cap * sizeof(*new_entries));
        if (!new_entries) ABORT("patch_add_entry: realloc failed");
        p->entries   = new_entries;
        p->entry_cap = new_cap;
    }

    p->entries[p->entry_count].orig_pc  = orig_pc;
    p->entries[p->entry_count].tramp_pc = tramp_pc;
    p->entry_count++;
}

static int redirect_if_inside_stolen_range(ucontext_t *uc)
{
    uint64_t cur_rip = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];

    patch_t *p, *tmp;
    HASH_ITER(hh, patches, p, tmp) {
        /*
         * Only care about RIPs that fall inside the overwritten range.
         * rip itself is the patch start;
         */
        if (cur_rip < p->rip || cur_rip >= p->rip + p->orig_len)
            continue;

        for (size_t i = 0; i < p->entry_count; i++) {
            if (p->entries[i].orig_pc == cur_rip) {
                DBG("[redir] RIP 0x%llx was inside patched stolen range "
                    "[0x%llx .. 0x%llx), redirecting to trampoline 0x%llx",
                    (unsigned long long)cur_rip,
                    (unsigned long long)p->rip,
                    (unsigned long long)(p->rip + p->orig_len),
                    (unsigned long long)p->entries[i].tramp_pc);

                uc->uc_mcontext.gregs[REG_RIP] = (greg_t)p->entries[i].tramp_pc;
                return 1;
            }
        }

        /*
         * We landed inside a patched range, but not on a known stolen
         * instruction boundary.
         */
        ABORT("RIP 0x%llx landed inside patched range [0x%llx .. 0x%llx) "
              "but no stolen-entry mapping exists",
              (unsigned long long)cur_rip,
              (unsigned long long)p->rip,
              (unsigned long long)(p->rip + p->orig_len));
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*                              Helpers                               */
/* ------------------------------------------------------------------ */
static long pagesize(void) { static long p=0; if(!p) p=sysconf(_SC_PAGESIZE); return p; }
static void die(const char *m){ perror(m); exit(1); }

static inline uint64_t masked_shadow_lo(void)
{
    if (!masked_secret || !encrypted_secret || !secret) return 0;
    return (uint64_t)encrypted_secret +
           ((uint64_t)masked_secret - (uint64_t)secret);
}

static inline uint64_t masked_shadow_hi(void)
{
    return masked_shadow_lo() + masked_secret_len;
}

/* Saves R8, RDI, R11, and R10 unless masked out.
 * If preserve_flags != 0, the helper also saves/restores RFLAGS.
 * If preserve_flags == 0, flags are left live so translated instructions
 * can define the outgoing flags seen by the original control flow.
 */
static inline uint8_t *save_regs(uint8_t *t, int mask, int preserve_flags)
{
    if (preserve_flags) {
        *t++ = 0x9C;   /* pushfq */
    }

    /* lea rsp, [rsp - 0xA0] */
    *t++ = 0x48; *t++ = 0x8D; *t++ = 0xA4; *t++ = 0x24;
    *t++ = 0x60; *t++ = 0xFF; *t++ = 0xFF; *t++ = 0xFF;

    /* [rsp+0x00] = r8 */
    if (!(mask & 8)) {
        *t++ = 0x4C; *t++ = 0x89; *t++ = 0x04; *t++ = 0x24;
    }
    /* [rsp+0x08] = rdi */
    if (!(mask & 1)) {
        *t++ = 0x48; *t++ = 0x89; *t++ = 0x7C; *t++ = 0x24; *t++ = 0x08;
    }
    /* [rsp+0x10] = r11 */
    if (!(mask & 2)) {
        *t++ = 0x4C; *t++ = 0x89; *t++ = 0x5C; *t++ = 0x24; *t++ = 0x10;
    }
    /* [rsp+0x18] = r10 */
    if (!(mask & 4)) {
        *t++ = 0x4C; *t++ = 0x89; *t++ = 0x54; *t++ = 0x24; *t++ = 0x18;
    }

    return t;
}

static inline uint8_t *restore_regs(uint8_t *t, int mask, int preserve_flags)
{
    if (!(mask & 4)) {           /* r10 <- [rsp+0x18] */
        *t++ = 0x4C; *t++ = 0x8B; *t++ = 0x54; *t++ = 0x24; *t++ = 0x18;
    }
    if (!(mask & 2)) {           /* r11 <- [rsp+0x10] */
        *t++ = 0x4C; *t++ = 0x8B; *t++ = 0x5C; *t++ = 0x24; *t++ = 0x10;
    }
    if (!(mask & 1)) {           /* rdi <- [rsp+0x08] */
        *t++ = 0x48; *t++ = 0x8B; *t++ = 0x7C; *t++ = 0x24; *t++ = 0x08;
    }
    if (!(mask & 8)) {           /* r8 <- [rsp] */
        *t++ = 0x4C; *t++ = 0x8B; *t++ = 0x04; *t++ = 0x24;
    }

    /* lea rsp, [rsp + 0xA0] */
    *t++ = 0x48; *t++ = 0x8D; *t++ = 0xA4; *t++ = 0x24;
    *t++ = 0xA0; *t++ = 0x00; *t++ = 0x00; *t++ = 0x00;

    if (preserve_flags) {
        *t++ = 0x9D;   /* popfq */
    }

    return t;
}


/* returns bit‑mask: 1=RDI, 2=R11, 4=R10 are DEST of [mem] load */
static int scratch_dest_mask(const cs_insn *i)
{
    const cs_x86  *x   = &i->detail->x86;
    if (x->op_count < 2) return 0;

    const cs_x86_op *dst = &x->operands[0];
    const cs_x86_op *src = &x->operands[1];

    if (dst->type != X86_OP_REG || src->type != X86_OP_MEM)
        return 0;

    switch (dst->reg) {
    case X86_REG_RDI:  case X86_REG_EDI:   return 1;   /* bit 0 */
    case X86_REG_R11:  case X86_REG_R11D:  return 2;   /* bit 1 */
    case X86_REG_R10:  case X86_REG_R10D:  return 4;   /* bit 2 */
    case X86_REG_R8:   case X86_REG_R8D:   return 8;   /* bit 3 */
    default:                              return 0;
    }
}

static int is_direct_branch(const cs_insn *i)
{
    switch (i->id) {
        /* unconditional */
        case X86_INS_JMP:
        case X86_INS_CALL:
        /* 0x70–0x7F short Jcc, 0F 80–8F near Jcc */
        case X86_INS_JAE: case X86_INS_JA:  case X86_INS_JBE:
        case X86_INS_JB:  case X86_INS_JCXZ:case X86_INS_JECXZ:
        case X86_INS_JE:  case X86_INS_JGE: case X86_INS_JG:
        case X86_INS_JLE: case X86_INS_JL:  case X86_INS_JNE:
        case X86_INS_JNO: case X86_INS_JNP: case X86_INS_JNS:
        case X86_INS_JO:  case X86_INS_JP:  case X86_INS_JS:
        case X86_INS_LOOP:
        case X86_INS_LOOPNE:
        case X86_INS_LOOPE:
            return 1;
        default:
            return 0;
    }
}


static int insn_is_store(const cs_insn *ci)
{
    const cs_x86 *x   = &ci->detail->x86;
    /* instructions with no memory operand */
    int have_mem = 0;
    for (int i = 0; i < x->op_count; i++)
        if (x->operands[i].type == X86_OP_MEM) { have_mem = 1; break; }
    if (!have_mem) return 0;

    /* opcode-based check (works with all Capstone versions) */
    switch (ci->id) {
        case X86_INS_MOV:
        case X86_INS_MOVQ:
        case X86_INS_MOVSB: case X86_INS_MOVSW:
        case X86_INS_MOVSD: case X86_INS_MOVSQ:
        case X86_INS_STOSB: case X86_INS_STOSW:
        case X86_INS_STOSD: case X86_INS_STOSQ:
        case X86_INS_CMPSB: case X86_INS_CMPSW:
        case X86_INS_CMPSD: case X86_INS_CMPSQ:
        case X86_INS_SCASB: case X86_INS_SCASW:
        case X86_INS_SCASD: case X86_INS_SCASQ:
        case X86_INS_XCHG:
        case X86_INS_ADD:  case X86_INS_SUB: case X86_INS_SBB:
        case X86_INS_INC:  case X86_INS_DEC:
        case X86_INS_XOR:  case X86_INS_OR:
        case X86_INS_AND:
        case X86_INS_VMOVDQA:
        case X86_INS_VMOVDQU:
            /* destination is operand 0 for all of the above */
            if (x->operands[0].type == X86_OP_MEM)
                return 1;
            return 0;
        default:
            return 0;
    }
}

static int insn_operand_reads_memory(const cs_insn *ci, int op_index)
{
    const cs_x86 *x = &ci->detail->x86;
    if (op_index < 0 || op_index >= x->op_count) return 0;
    if (x->operands[op_index].type != X86_OP_MEM) return 0;

    switch (ci->id) {
        /* real loads / load side of RMW */
        case X86_INS_MOV:
        case X86_INS_MOVQ:
        case X86_INS_MOVZX:
        case X86_INS_MOVSX:
        case X86_INS_MOVSXD:
        case X86_INS_CMP:
        case X86_INS_TEST:
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_SBB:
        case X86_INS_XOR:
        case X86_INS_OR:
        case X86_INS_AND:
        case X86_INS_MUL:
        case X86_INS_MOVAPS:
        case X86_INS_MOVUPS:
        case X86_INS_MOVAPD:
        case X86_INS_MOVUPD:
        case X86_INS_MOVDQA:
        case X86_INS_MOVDQU:
        case X86_INS_VMOVDQA:
        case X86_INS_VMOVDQU:
        case X86_INS_VMOVDQU32:
        case X86_INS_VMOVDQU64:
        case X86_INS_MOVSB:
        case X86_INS_MOVSW:
        case X86_INS_MOVSD:
        case X86_INS_MOVSQ:
        case X86_INS_CMPSB:
        case X86_INS_CMPSW:
        case X86_INS_CMPSD:
        case X86_INS_CMPSQ:
        case X86_INS_SCASB:
        case X86_INS_SCASW:
        case X86_INS_SCASD:
        case X86_INS_SCASQ:
            return 1;

        /* address-generation only / fake mem syntax */
        case X86_INS_LEA:
        case X86_INS_NOP:
            return 0;

        default:
            /* conservative default:
               if the instruction has a mem operand and is not LEA/NOP,
               assume it may read if operand 0 is MEM or operand 1 is MEM. */
            return 1;
    }
}

/* record the main thread’s stack */
static void *stack_base;
static size_t stack_size;

__attribute__((constructor))
static void capture_stack_bounds(void) {
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) == 0) {
        pthread_attr_getstack(&attr, &stack_base, &stack_size);
        pthread_attr_destroy(&attr);
    } else {
        ABORT("pthread_getattr_np() failed – cannot determine main-thread stack");
    }
}

/* try to reserve RWX memory within ±1.5 GiB of rip */
static void *alloc_near(uint64_t rip, size_t len)
{
    /* start 1.5 GiB below RIP, step… */
    const uint64_t window = 0x60000000ULL;      // 1.5 GiB
    uint64_t lo = (rip > window) ? rip - window : 0x10000;
    lo &= ~(pagesize() - 1);      // round down
    uint64_t hi = rip + window;

    for (uint64_t addr = lo; addr < hi; addr += 0x10000) {
        /* skip the saved stack region */
        if ((void*)addr >= stack_base &&
            (void*)addr <  (void*)((char*)stack_base + stack_size))
            continue;
        void *p = mmap((void *)addr, len,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS |
                       MAP_FIXED_NOREPLACE,       /* don’t clobber anything */
                       -1, 0);
        if (p != MAP_FAILED)
            return p;            /* found a suitable mapping */
    }
    /*
     * If we really couldn’t find a free 64 KiB-aligned slot
     * within ±1.5 GiB, fall back to mmap in the *lower* 2 GiB
     * (MAP_32BIT), so rel32 branches from anywhere in the low
     * 2 GiB will still reach us.
     */
    void *p = mmap(NULL, len,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1, 0);
    if (p != MAP_FAILED)
        return p;
    return NULL;
}

/* ---------- helper to map Capstone register → ModRM rm-id (0-15) -------- */
/* Return Intel reg-id (0-15) suitable for ModRM/REX, or -1 on error.      */
static int rm_id(const cs_x86_op *r)
{
    switch (r->reg) {
    /* ------------------------------- low eight ------------------------------- */
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: return 0;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: return 1;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: return 2;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: return 3;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP:                    return 4;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP:                    return 5;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI:                    return 6;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI:                    return 7;

    /* SPL/BPL/SIL/DIL need a REX prefix but still map to 4-7 */
    case X86_REG_SPL: return 4;
    case X86_REG_BPL: return 5;
    case X86_REG_SIL: return 6;
    case X86_REG_DIL: return 7;

    /* ------------- high eight (r8–r15) – every size variant ----------------- */
    case X86_REG_R8  : case X86_REG_R8D : case X86_REG_R8W : case X86_REG_R8B  : return  8;
    case X86_REG_R9  : case X86_REG_R9D : case X86_REG_R9W : case X86_REG_R9B  : return  9;
    case X86_REG_R10 : case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B : return 10;
    case X86_REG_R11 : case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B : return 11;
    case X86_REG_R12 : case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B : return 12;
    case X86_REG_R13 : case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B : return 13;
    case X86_REG_R14 : case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B : return 14;
    case X86_REG_R15 : case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B : return 15;

    default: return -1;   /* any MMX/XMM, segment regs, etc. – we abort earlier */
    }
}

static int xmm_id(x86_reg r)
{
    switch (r) {
    case X86_REG_XMM0:  return 0;
    case X86_REG_XMM1:  return 1;
    case X86_REG_XMM2:  return 2;
    case X86_REG_XMM3:  return 3;
    case X86_REG_XMM4:  return 4;
    case X86_REG_XMM5:  return 5;
    case X86_REG_XMM6:  return 6;
    case X86_REG_XMM7:  return 7;
    case X86_REG_XMM8:  return 8;
    case X86_REG_XMM9:  return 9;
    case X86_REG_XMM10: return 10;
    case X86_REG_XMM11: return 11;
    case X86_REG_XMM12: return 12;
    case X86_REG_XMM13: return 13;
    case X86_REG_XMM14: return 14;
    case X86_REG_XMM15: return 15;
    default:
        return -1;
    }
}

/* translate Capstone register -> glibc ucontext index */
static int greg_for(x86_reg r)
{
    switch (r) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: return REG_RAX;
    case X86_REG_RBX: case X86_REG_EBX:                                     return REG_RBX;
    case X86_REG_RCX: case X86_REG_ECX:                                     return REG_RCX;
    case X86_REG_RDX: case X86_REG_EDX:                                     return REG_RDX;
    case X86_REG_RSI: case X86_REG_ESI:                                     return REG_RSI;
    case X86_REG_RDI: case X86_REG_EDI:                                     return REG_RDI;
    case X86_REG_RBP: case X86_REG_EBP:                                     return REG_RBP;
    case X86_REG_RSP: case X86_REG_ESP:                                     return REG_RSP;
    case X86_REG_R8 : case X86_REG_R8D :                                    return REG_R8;
    case X86_REG_R9 : case X86_REG_R9D :                                    return REG_R9;
    case X86_REG_R10: case X86_REG_R10D:                                    return REG_R10;
    case X86_REG_R11: case X86_REG_R11D:                                    return REG_R11;
    case X86_REG_R12: case X86_REG_R12D:                                    return REG_R12;
    case X86_REG_R13: case X86_REG_R13D:                                    return REG_R13;
    case X86_REG_R14: case X86_REG_R14D:                                    return REG_R14;
    case X86_REG_R15: case X86_REG_R15D:                                    return REG_R15;
    default: return -1;
    }
}

/* given ucontext + Capstone mem-operand → return absolute EA */
static uint64_t effective_addr(const ucontext_t *uc,
                               const cs_x86_op *mem,
                               uint64_t ins_addr,
                               size_t ins_size)
{
    uint64_t base = 0, index = 0;

    /* RIP-relative uses NEXT RIP, not current RIP */
    if (mem->mem.base == X86_REG_RIP) {
        return ins_addr + ins_size + mem->mem.disp;
    }

    if (!uc)
        ABORT("effective_addr: uc==NULL for non-RIP-relative operand");

    if (mem->mem.base != X86_REG_INVALID)
        base = uc->uc_mcontext.gregs[ greg_for(mem->mem.base) ];
    if (mem->mem.index != X86_REG_INVALID)
        index = uc->uc_mcontext.gregs[ greg_for(mem->mem.index) ];

    return base + index * mem->mem.scale + mem->mem.disp;
}

static int insn_has_rip_relative_mem(const cs_insn *ins, const cs_x86_op **mem_out)
{
    const cs_x86 *x = &ins->detail->x86;
    for (int i = 0; i < x->op_count; i++) {
        const cs_x86_op *op = &x->operands[i];
        if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
            if (mem_out) *mem_out = op;
            return 1;
        }
    }
    if (mem_out) *mem_out = NULL;
    return 0;
}

static size_t riprel_disp_offset_fallback(const cs_insn *ins)
{
    const cs_x86 *x = &ins->detail->x86;

    /* Best case: Capstone gives us a sane displacement offset. */
    if (x->encoding.disp_offset > 0 &&
        x->encoding.disp_offset + 4 <= ins->size) {
        return x->encoding.disp_offset;
    }

    /* Fallback: for normal x86-64 RIP-relative memory operands,
       the displacement is disp32 at the tail of the instruction. */
    if (ins->size < 4)
        ABORT("riprel_disp_offset_fallback: instruction too short: %s %s",
              ins->mnemonic, ins->op_str);

    return ins->size - 4;
}

static uint8_t *emit_load_from_shadow(uint8_t *p,
                                      const cs_x86_op *dst,
                                      size_t width,
                                      uint64_t src_abs,
                                      int sign_extend);

static uint8_t *emit_store_to_shadow(uint8_t *p,
                                     const cs_x86_op *src,
                                     size_t width,
                                     uint64_t dst_abs);

static uint8_t *emit_relocated_rip_relative_insn(uint8_t *t, const cs_insn *ins)
{
    const cs_x86 *x = &ins->detail->x86;
    const cs_x86_op *mop = NULL;
    int mem_index = -1;

    for (int i = 0; i < x->op_count; i++) {
        if (x->operands[i].type == X86_OP_MEM &&
            x->operands[i].mem.base == X86_REG_RIP) {
            mop = &x->operands[i];
            mem_index = i;
            break;
        }
    }
    if (!mop)
        ABORT("emit_relocated_rip_relative_insn: no RIP-relative mem operand");

    uint64_t target = effective_addr(NULL, mop, ins->address, ins->size);

    DBG("RIP-rel relocate: %s %s  size=%u target=0x%llx",
        ins->mnemonic, ins->op_str,
        ins->size, (unsigned long long)target);

    /* ---------------------------
       Case A: LEA reg, [rip+disp]
       --------------------------- */
    if (ins->id == X86_INS_LEA) {
        const cs_x86_op *dop = NULL;
        for (int i = 0; i < x->op_count; i++) {
            if (x->operands[i].type == X86_OP_REG) {
                dop = &x->operands[i];
                break;
            }
        }
        if (!dop)
            ABORT("emit_relocated_rip_relative_insn: RIP-relative LEA missing dst reg");

        int dst_id = rm_id(dop);
        if (dst_id < 0)
            ABORT("emit_relocated_rip_relative_insn: bad LEA dst reg");

        bool dst_is_64 = (dop->size == 8);

        uint8_t rex = 0x40;
        if (dst_is_64) rex |= 0x08;
        if (dst_id & 8) rex |= 0x04;
        if (rex != 0x40) *t++ = rex;

        *t++ = 0x8D;
        *t++ = (uint8_t)(((dst_id & 7) << 3) | 0x05);

        int64_t rel64 = (int64_t)target - (int64_t)((uint64_t)t + 4);
        if (rel64 < INT32_MIN || rel64 > INT32_MAX) {
            /* fallback: movabs dst, imm64 */
            t -= 2;                    /* remove opcode/modrm */
            if (rex != 0x40) t -= 1;   /* remove rex if emitted */

            if (dst_is_64) {
                uint8_t rex2 = 0x48;
                if (dst_id & 8) rex2 |= 0x01;   /* movabs uses B bit */
                *t++ = rex2;
                *t++ = (uint8_t)(0xB8 + (dst_id & 7));
                memcpy(t, &target, 8); t += 8;
                return t;
            }

            ABORT("emit_relocated_rip_relative_insn: non-64-bit LEA fallback unsupported");
        }

        int32_t disp = (int32_t)rel64;
        memcpy(t, &disp, 4);
        t += 4;
        return t;
    }

    /* ---------------------------------------------------
       Case B: reg <- [rip+disp]   or   [rip+disp] <- reg
       --------------------------------------------------- */

    if (mem_index == 1 && x->operands[0].type == X86_OP_REG) {
        /* LOAD form */

        const cs_x86_op *dst = &x->operands[0];

        /* ---------- vector load fallback ---------- */
        if ((dst->reg >= X86_REG_XMM0 && dst->reg <= X86_REG_XMM15) ||
            (dst->reg >= X86_REG_YMM0 && dst->reg <= X86_REG_YMM15)) {
            size_t width = (dst->reg >= X86_REG_YMM0 && dst->reg <= X86_REG_YMM15) ? 32 : 16;

            /* preserve architectural RDI: emit_load_from_shadow() uses RDI as base */
            *t++ = 0x57;                    /* push rdi */
            t = emit_load_from_shadow(t, dst, width, target, 0);
            *t++ = 0x5F;                    /* pop  rdi */
            return t;
        }

        /* ---------- GPR load: try rel32 patch first ---------- */
        {
            size_t disp_off = riprel_disp_offset_fallback(ins);
            int64_t new_rel64 = (int64_t)target - (int64_t)((uint64_t)t + ins->size);

            if (new_rel64 >= INT32_MIN && new_rel64 <= INT32_MAX) {
                memcpy(t, ins->bytes, ins->size);
                int32_t new_disp = (int32_t)new_rel64;
                memcpy(t + disp_off, &new_disp, 4);
                return t + ins->size;
            }
        }

        /* ---------- GPR absolute fallback ---------- */
        {
            int dst_id = rm_id(dst);
            if (dst_id < 0)
                ABORT("emit_relocated_rip_relative_insn: bad GPR dst");

            *t++ = 0x41; *t++ = 0x52;          /* push r10 */

            /* movabs r10, target */
            *t++ = 0x49; *t++ = 0xBA;
            memcpy(t, &target, 8); t += 8;

            /* mov dst, [r10]  */
            if (dst->size == 2) *t++ = 0x66;

            uint8_t rex = 0x40;
            if (dst->size == 8) rex |= 0x08;
            if (dst_id & 8)     rex |= 0x04;   /* reg */
            rex |= 0x01;                       /* rm = r10 */
            if (rex != 0x40) *t++ = rex;

            *t++ = 0x8B;
            *t++ = (uint8_t)(((dst_id & 7) << 3) | 0x02);

            *t++ = 0x41; *t++ = 0x5A;          /* pop  r10 */
            return t;
        }
    }

    if (mem_index == 0 && x->op_count >= 2 && x->operands[1].type == X86_OP_REG) {
        /* STORE form */

        const cs_x86_op *src = &x->operands[1];

        /* vector store fallback */
        if ((src->reg >= X86_REG_XMM0 && src->reg <= X86_REG_XMM15) ||
            (src->reg >= X86_REG_YMM0 && src->reg <= X86_REG_YMM15)) {
            size_t width = (src->reg >= X86_REG_YMM0 && src->reg <= X86_REG_YMM15) ? 32 : 16;

            /* preserve architectural RDI: emit_store_to_shadow() uses RDI as base */
            *t++ = 0x57;                    /* push rdi */
            t = emit_store_to_shadow(t, src, width, target);
            *t++ = 0x5F;                    /* pop  rdi */
            return t;
        }

        /* GPR store: try rel32 patch first */
        {
            size_t disp_off = riprel_disp_offset_fallback(ins);
            int64_t new_rel64 = (int64_t)target - (int64_t)((uint64_t)t + ins->size);

            if (new_rel64 >= INT32_MIN && new_rel64 <= INT32_MAX) {
                memcpy(t, ins->bytes, ins->size);
                int32_t new_disp = (int32_t)new_rel64;
                memcpy(t + disp_off, &new_disp, 4);
                return t + ins->size;
            }
        }

        /* GPR absolute fallback */
        {
            int src_id = rm_id(src);
            if (src_id < 0)
                ABORT("emit_relocated_rip_relative_insn: bad GPR src");

            *t++ = 0x41; *t++ = 0x52;          /* push r10 */

            /* movabs r10, target */
            *t++ = 0x49; *t++ = 0xBA;
            memcpy(t, &target, 8); t += 8;

            if (src->size == 2) *t++ = 0x66;

            uint8_t rex = 0x40;
            if (src->size == 8) rex |= 0x08;
            if (src_id & 8)     rex |= 0x04;   /* reg */
            rex |= 0x01;                       /* rm = r10 */
            if (rex != 0x40) *t++ = rex;

            *t++ = 0x89;
            *t++ = (uint8_t)(((src_id & 7) << 3) | 0x02);

            *t++ = 0x41; *t++ = 0x5A;          /* pop  r10 */
            return t;
        }
    }

    ABORT("emit_relocated_rip_relative_insn: unsupported RIP-relative instruction %s %s",
          ins->mnemonic, ins->op_str);
    return t;
}

/* ------------------------------------------------------------------ */
/*                       Debug Printing Helpers                       */
/* ------------------------------------------------------------------ */

// Disassemble and print the instruction at RIP.
static void print_instruction(uint64_t rip)
{
    uint8_t code[16] = {0};
    memcpy(code, (const void *)rip, sizeof(code));

    cs_insn *insn = NULL;
    size_t count = cs_disasm(cs, code, sizeof(code), rip, 1, &insn);
    if (count == 1) {
        DBG("Faulting instruction at 0x%llx: %s %s (size: %u bytes)",
            (unsigned long long)rip,
            insn[0].mnemonic,
            insn[0].op_str,
            insn[0].size);
        cs_free(insn, count);
        return;
    }

    DBG("Failed to disassemble instruction at 0x%llx",
        (unsigned long long)rip);
}

static void dump_code(uint64_t rip, size_t bytes)
{
    uint8_t buf[64];
    if (bytes > sizeof buf) bytes = sizeof buf;
    memcpy(buf, (void*)rip, bytes);

    cs_insn *ins;
    size_t n = cs_disasm(cs, buf, bytes, rip, 0, &ins);
    for (size_t i = 0; i < n; i++)
        DBG("  %12llx: %-8s %s", (unsigned long long)ins[i].address,
                                  ins[i].mnemonic, ins[i].op_str);
    cs_free(ins, n);
}

static void dump_bytes_as_code(const uint8_t *buf, size_t len, uint64_t addr)
{
    cs_insn *ins;
    size_t n = cs_disasm(cs, buf, len, addr, 0, &ins);
    for (size_t i = 0; i < n; i++)
        DBG("  %12llx: %-8s %s",
            (unsigned long long)ins[i].address,
            ins[i].mnemonic, ins[i].op_str);
    cs_free(ins, n);
}

/* Disassemble N instructions before and after `rip` and highlight it */
static void dump_code_around(uint64_t rip, int before, int after)
{
    const size_t PAGE     = pagesize();                  /* 4 KiB                         */
    const uintptr_t plo   = rip & ~(PAGE - 1);           /* page start that holds <rip>   */
    const uintptr_t phi   = plo + PAGE;                  /* first byte of next page       */

    /* pessimistic “bytes we might need” */
    size_t want_back = before * 15 + 16;                 /* 15 B worst-case insn + pad    */
    size_t want_fwd  = after  * 15 + 16;

    /* clamp to the page actually mapped */
    size_t back_ok   = rip - plo;
    if (want_back > back_ok) want_back = back_ok;
    size_t fwd_ok    = phi - rip - 1;
    if (want_fwd  > fwd_ok)  want_fwd  = fwd_ok;

    const uint8_t *start   = (const uint8_t *)(rip - want_back);
    const size_t   buf_len = want_back + want_fwd;

    /* ---- heap, not alloca, so the alt-stack never blows up ---- */
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    if (!buf) return;                                     /* OOM? just give up             */

    memcpy(buf, start, buf_len);                          /* guaranteed inside same page   */

    cs_insn *ins;
    size_t n = cs_disasm(cs, buf, buf_len, (uint64_t)start, 0, &ins);
    if (!n) { free(buf); return; }

    ssize_t idx = -1;
    for (size_t i = 0; i < n; ++i)
        if (ins[i].address == rip) { idx = (ssize_t)i; break; }
    if (idx < 0) { cs_free(ins, n); free(buf); return; }

    ssize_t first = idx - before;  if (first < 0) first = 0;
    ssize_t last  = idx + after;   if (last  >= (ssize_t)n) last = (ssize_t)n - 1;

    for (ssize_t i = first; i <= last; ++i) {
        DBG("%s%12llx: %-8s %s",
            (i == idx ? "=> " : "   "),
            (unsigned long long)ins[i].address,
            ins[i].mnemonic, ins[i].op_str);
    }

    cs_free(ins, n);
    free(buf);
}



/* ------------------------------------------------------------------ */
/*                    Trampoline Emission Helpers                     */
/* ------------------------------------------------------------------ */

/* Emit “lea r11,[mem]” – where `mem` is the *original* Capstone       */
/* memory operand of the faulting/stolen instruction.                 */
/* Returns updated pointer.  Uses NO other registers.                  */
static uint8_t *emit_lea_r11(uint8_t *p,
                             const cs_x86_op *mem,
                             uint64_t orig_insn_addr,
                             size_t insn_size)
{
    /* ----------------------------------------------------------------
       We must rebuild exactly the ModRM/SIB the CPU decoded originally.
       Rules:
         *   base  and index  come from mem->mem.{base,index}
         *   disp  is mem->mem.disp (already sign‑extended to 64 b)
         *   scale is mem->mem.scale (1,2,4,8)
       For RIP‑relative (base == RIP) we just do movabs r11, EA.
       ----------------------------------------------------------------*/
    if (mem->mem.base == X86_REG_RIP) {
        uint64_t ea = orig_insn_addr + insn_size + mem->mem.disp;
        *p++ = 0x49; *p++ = 0xBB;                /* movabs r11, imm64 */
        memcpy(p, &ea, 8); p += 8;
        return p;
    }

    /* ---------------- build REX prefix ---------------- */
    uint8_t rex = 0x4C;                  /* 0100 | W=1 | R=1 | X=0 | B=0
                                            W=1 (64‑bit), R selects r11
                                            X/B will be patched below   */
    int base = rm_id(&(cs_x86_op){ .type = X86_OP_REG, .reg  = mem->mem.base });  /* id for base register */
    int index= -1;
    if (mem->mem.index != X86_REG_INVALID)
        index = rm_id(&(cs_x86_op){.type=X86_OP_REG,.reg=mem->mem.index});
    if (base & 8)  rex |= 0x01;          /* B bit */
    if (index>=0 && (index & 8)) rex |= 0x02;   /* X bit */
    if (rex != 0x40) *p++ = rex;

    /* ------------ LEA opcode + ModRM/SIB/disp ---------- */
    *p++ = 0x8D;                         /* LEA r/m64 -> r64 */

    /* decide whether we need a SIB byte */
    int need_sib = (mem->mem.index != X86_REG_INVALID) ||
                   (base & 7) == 4 /*RSP*/ || (base & 7) == 5 /*RBP*/;

    /* ---------------------- ModRM ----------------------- */
    uint8_t modrm = 0;
    uint8_t disp_size = 0;
    if (mem->mem.disp == 0 &&
        (base & 7) != 5) {               /* no disp, base≠RBP */
        modrm = 0x00;                    /* [base] */
    } else if ((int32_t)mem->mem.disp == mem->mem.disp) {
        modrm = 0x80; disp_size = 4;     /* disp32 */
    } else {                             /* disp8 impossible – huge disp */
        modrm = 0x80; disp_size = 4;
    }
    modrm |= (3 /*r11*/ & 7) << 3;       /* reg field */
    modrm |= need_sib ? 4 : (base & 7);  /* r/m field */
    *p++ = modrm;

    /* ---------------------- SIB (if any) ---------------------- */
    if (need_sib) {
        uint8_t sib = 0;
        int scale_field = (mem->mem.scale == 1)?0 :
                          (mem->mem.scale == 2)?1 :
                          (mem->mem.scale == 4)?2 : 3;
        sib |= scale_field << 6;
        sib |= (index>=0 ? (index & 7) : 4) << 3;  /* index 4 = none */
        sib |= (base & 7);
        *p++ = sib;
    }

    /* ---------------------- displacement ---------------------- */
    if (disp_size) {
        int32_t d32 = (int32_t)mem->mem.disp;
        memcpy(p, &d32, 4);  p += 4;
    }
    return p;
}

/* emit “add r11, SHADOW_DELTA” only when EA ∈ [secret, secret+secret_len) */
static inline uint8_t *emit_add_r11_imm(uint8_t *p, int64_t delta)
{
    uint8_t *skip_low = NULL, *skip_high = NULL;
    uint64_t sec_lo   = (uint64_t)secret;
    uint64_t sec_hi   = (uint64_t)secret + secret_len;

    /* preserve architectural r8 across repeated EA recomputation */
    *p++ = 0x41; *p++ = 0x50;               /* push r8 */

    // 1) load secret base → r8
    *p++ = 0x49; *p++ = 0xB8;                /* mov r8, imm64 */
    memcpy(p, &sec_lo, 8); p += 8;

    // 2) cmp r11, r8
    *p++ = 0x4D; *p++ = 0x39; *p++ = 0xC3;  /* cmp r11, r8 */

    // 3) jb .skip_add
    *p++ = 0x0F; *p++ = 0x82;               /* JB rel32 */
    skip_low = p; memset(p, 0, 4); p += 4;

    // 4) load secret_hi → r8
    *p++ = 0x49; *p++ = 0xB8;               /* mov r8, imm64 */
    memcpy(p, &sec_hi, 8); p += 8;

    // 5) cmp r11, r8
    *p++ = 0x4D; *p++ = 0x39; *p++ = 0xC3;  /* cmp r11, r8 */

    // 6) jae .skip_add
    *p++ = 0x0F; *p++ = 0x83;               /* JAE rel32 */
    skip_high = p; memset(p, 0, 4); p += 4;

    // 7) inside secret: do the add/shadow mapping
    if ((int32_t)delta == delta) {
        *p++ = 0x49; *p++ = 0x81; *p++ = 0xC3;  /* add r11, imm32 */
        int32_t d32 = (int32_t)delta;
        memcpy(p, &d32, 4); p += 4;
    } else {
        *p++ = 0x49; *p++ = 0xB8;               /* movabs r8, imm64 */
        memcpy(p, &delta, 8); p += 8;
        *p++ = 0x4D; *p++ = 0x01; *p++ = 0xC3;  /* add r11, r8 */
    }

    // 8) patch the two rel32s so they skip over the add
    /* pop r8 must run on both paths (taken / not taken) */
    uint8_t *skip_target = p;
    *p++ = 0x41; *p++ = 0x58;               /* pop r8 */

    {
        int32_t disp;

        disp = (int32_t)(skip_target - (skip_low + 4));
        memcpy(skip_low, &disp, 4);

        disp = (int32_t)(skip_target - (skip_high + 4));
        memcpy(skip_high, &disp, 4);
    }
    return p;
}

/* --------------------- emit “cmp r11, immXX / reg” ---------------------*/
static inline uint8_t *emit_cmp_r11(uint8_t *t,
                                    const cs_x86_op *rhs,   /* IMM or REG */
                                    size_t width)           /* 1/2/4/8    */
{
    if (rhs->type == X86_OP_IMM) {
        /* choose correct operand width; width is in BYTES: 1/2/4/8 */
        if (width == 1) {                 /* cmp r11b, imm8 */
            *t++ = 0x41; *t++ = 0x80; *t++ = 0xFB;
            *t++ = (uint8_t)rhs->imm;
        } else if (width == 2) {          /* cmp r11w, imm16 */
            *t++ = 0x66; *t++ = 0x41; *t++ = 0x81; *t++ = 0xFB;
            uint16_t v = (uint16_t)rhs->imm;
            memcpy(t, &v, 2); t += 2;
        } else if (width == 4) {          /* cmp r11d, imm32 */
            *t++ = 0x41; *t++ = 0x81; *t++ = 0xFB;
            uint32_t v = (uint32_t)rhs->imm;
            memcpy(t, &v, 4); t += 4;
        } else if (width == 8) {          /* cmp r11, imm32 (sign-extended) */
            *t++ = 0x49; *t++ = 0x81; *t++ = 0xFB;
            uint32_t v = (uint32_t)rhs->imm;
            memcpy(t, &v, 4); t += 4;
        } else {
            ABORT("emit_cmp_r11: bad immediate width %zu", width);
        }
    } else {                              /* rhs is a register */
        uint8_t id = rm_id(rhs);          /* src id */
        uint8_t rex = 0x40;
        if (width == 8) rex |= 0x08;       /* W */
        if (id & 8)   rex |= 0x01;         /* B (goes in r/m) */
        rex           |= 0x04;             /* R (r11 high bit) */
        if (rex != 0x40) *t++ = rex;
        if (width == 2) *t++ = 0x66;
        *t++ = 0x39;                       /* cmp r/m, reg */
        *t++ = 0xD8 | (id & 7);            /* r/m = r11 (3), reg = id */
    }
    return t;
}


static bool dest_is_scratch_and_src_is_mem(const cs_insn *i)
{
    const cs_x86 *x = &i->detail->x86;
    if (x->op_count < 2)
        return false;

    const cs_x86_op *dst = &x->operands[0];
    const cs_x86_op *src = &x->operands[1];

    /* pattern:  {RDI|R11|R10} ← [mem]   (any width) */
    if (dst->type == X86_OP_REG &&
        src->type == X86_OP_MEM) {
        switch (dst->reg) {
        case X86_REG_RDI:  case X86_REG_EDI:
        case X86_REG_R11:  case X86_REG_R11D:
        case X86_REG_R10:  case X86_REG_R10D:
            return true;
        default:
            break;
        }
    }
    /* MOVZX / MOVSX use the same operand order, so this single
       test also catches those variants. */
    return false;
}


/* Emit: if (r11 < secret || r11 >= secret+secret_len)  jmp skip */
static inline uint8_t *emit_branch_if_not_secret(uint8_t *p, uint8_t **patch_site_low, uint8_t **patch_site_high, int use_r10)
{
    uint64_t lo = masked_shadow_lo();
    uint64_t hi = masked_shadow_hi();

    const uint8_t mov_opcode = use_r10 ? 0xBA /*r10*/ : 0xB8 /*r8*/;
    const uint8_t cmp_modrm  = use_r10 ? 0xD3 /*r10*/ : 0xC3 /*r8*/;


    /* cmp r11,lo   /  jb  skip */
    *p++ = 0x49; *p++ = mov_opcode;          /* movabs scratch, lo */
    memcpy(p,&lo,8);  p += 8;
    *p++ = 0x4D; *p++ = 0x39; *p++ = cmp_modrm; /* cmp r11,scratch  */
    *p++ = 0x0F; *p++ = 0x82;                               /* jb rel32  */
    *patch_site_low  = p;  memset(p,0,4);  p += 4;

    /* cmp r11,hi   /  jae skip */
    *p++ = 0x49; *p++ = mov_opcode;          /* movabs scratch, lo */
    memcpy(p,&hi,8);  p += 8;
    *p++ = 0x4D; *p++ = 0x39; *p++ = cmp_modrm; /* cmp r11,scratch  */
    *p++ = 0x0F; *p++ = 0x83;                               /* jae rel32 */
    *patch_site_high = p; memset(p,0,4);  p += 4;

   
    return p;
}

static inline uint8_t *emit_branch_if_not_shadow_addrreg(uint8_t *p,
                                                         uint8_t **patch_site_low,
                                                         uint8_t **patch_site_high,
                                                         int addr_reg_is_rdi,
                                                         int use_r10_scratch)
/* addr_reg_is_rdi:
 *   0 -> compare r11 against [encrypted_secret, encrypted_secret+secret_len)
 *   1 -> compare rdi against [encrypted_secret, encrypted_secret+secret_len)
 *
 * scratch:
 *   0 -> use r8
 *   1 -> use r10
 */
{
    uint64_t lo = masked_shadow_lo();
    uint64_t hi = masked_shadow_hi();

    if (!use_r10_scratch) {
        /* movabs r8, lo */
        *p++ = 0x49; *p++ = 0xB8;
        memcpy(p, &lo, 8); p += 8;

        if (addr_reg_is_rdi) {
            /* cmp rdi, r8 */
            *p++ = 0x4C; *p++ = 0x39; *p++ = 0xC7;
        } else {
            /* cmp r11, r8 */
            *p++ = 0x4D; *p++ = 0x39; *p++ = 0xC3;
        }

        /* jb skip */
        *p++ = 0x0F; *p++ = 0x82;
        *patch_site_low = p; memset(p, 0, 4); p += 4;

        /* movabs r8, hi */
        *p++ = 0x49; *p++ = 0xB8;
        memcpy(p, &hi, 8); p += 8;

        if (addr_reg_is_rdi) {
            /* cmp rdi, r8 */
            *p++ = 0x4C; *p++ = 0x39; *p++ = 0xC7;
        } else {
            /* cmp r11, r8 */
            *p++ = 0x4D; *p++ = 0x39; *p++ = 0xC3;
        }

        /* jae skip */
        *p++ = 0x0F; *p++ = 0x83;
        *patch_site_high = p; memset(p, 0, 4); p += 4;

        return p;
    }

    /* ---- same logic, but use r10 instead of r8 ---- */

    /* movabs r10, lo */
    *p++ = 0x49; *p++ = 0xBA;
    memcpy(p, &lo, 8); p += 8;

    if (addr_reg_is_rdi) {
        /* cmp rdi, r10 */
        *p++ = 0x4C; *p++ = 0x39; *p++ = 0xD7;
    } else {
        /* cmp r11, r10 */
        *p++ = 0x4D; *p++ = 0x39; *p++ = 0xD3;
    }

    /* jb skip */
    *p++ = 0x0F; *p++ = 0x82;
    *patch_site_low = p; memset(p, 0, 4); p += 4;

    /* movabs r10, hi */
    *p++ = 0x49; *p++ = 0xBA;
    memcpy(p, &hi, 8); p += 8;

    if (addr_reg_is_rdi) {
        /* cmp rdi, r10 */
        *p++ = 0x4C; *p++ = 0x39; *p++ = 0xD7;
    } else {
        /* cmp r11, r10 */
        *p++ = 0x4D; *p++ = 0x39; *p++ = 0xD3;
    }

    /* jae skip */
    *p++ = 0x0F; *p++ = 0x83;
    *patch_site_high = p; memset(p, 0, 4); p += 4;

    return p;
}

/* XOR the register in `dst` with the mask byte‑pattern that starts  */
/* exactly `MASK_DELTA` bytes away from the current shadow address   */
/* (that address is still in r11 when this is called).               */
/* Handles GPR (1/2/4/8‑byte) and XMM/YMM (16/32‑byte) destinations. */
static inline uint8_t *emit_xor_with_mask(uint8_t *p,
                                          const cs_x86_op *dst,
                                          size_t width,
                                          int     is_vector /* 0=GPR 1=XMM 2=YMM */)
{
    #if !PDM_MASKING
        (void)dst; (void)width; (void)is_vector;
        return p;
    #else
    if (is_vector) {
        /* r11 holds EA.  First: branch away if EA ∉ secret. */
        uint8_t *skip_low, *skip_high;
        p = emit_branch_if_not_secret(p, &skip_low, &skip_high, 1);

        /* r10 = r11 + MASK_DELTA  (mask line) */
        *p++ = 0x4D; *p++ = 0x8D; *p++ = 0x93;           /* lea r10,[r11+disp32] */
        int32_t d32 = (int32_t)MASK_DELTA;  memcpy(p,&d32,4);  p += 4;

        /* ---- build 3‑byte VEX, VPXOR dst,dst,[r10] ---- */
        int dst_id = (dst->reg >= X86_REG_YMM0)
                     ? dst->reg - X86_REG_YMM0
                     : dst->reg - X86_REG_XMM0;
        int is_ymm = (is_vector==2);

        uint8_t vex2 = 0x41;                           /* X'=1, B'=0, m=00001 */
        vex2 |= ((dst_id & 8) ? 0 : 0x80);             /* R'                */
        uint8_t vex3 = ((~dst_id & 0xF) << 3)          /* vvvv              */
                       | (is_ymm ? 0x04 : 0)           /* L                 */
                       | 0x01;                         /* pp=66             */
        *p++ = 0xC4; *p++ = vex2; *p++ = vex3;
        *p++ = 0xEF;                                   /* VPXOR opcode      */
        *p++ = 0x02 | ((dst_id & 7)<<3);               /* rm=r10            */

        /* ---- patch the two skip‑targets to jump here ---- */
        {
            uint8_t *end = p;
            int32_t rel;

            rel = (int32_t)(end - (skip_low + 4));
            memcpy(skip_low,  &rel, 4);
            rel = (int32_t)(end - (skip_high + 4));
            memcpy(skip_high, &rel, 4);
        }
        return p;
    }


/* ───────── scalar GPRs: load mask from secret_mask_page ─────────
 *
 * IMPORTANT:
 * - Usually r11 still holds the shadow address.
 * - But if dst == r11, then the preceding load clobbered r11 with the loaded value.
 *   In that case, emit_load_from_shadow() left the shadow address in rdi.
 */
const int dst_id  = rm_id(dst);
const int tmp_id  = (dst_id == 10) ? 8 : 10;   /* use r8 if dst==r10, else r10 */
const int addr_id = (dst_id == 11) ? 7 : 11;   /* use rdi if dst==r11, else r11 */

uint8_t *skip_low = NULL, *skip_high = NULL;
int addr_reg_is_rdi = (addr_id == 7);

/*
 * Critical bug fix:
 * if dst is r8/r8d/r8w/r8b, do NOT use r8 as the compare scratch in the
 * shadow-range test, or the just-loaded architectural destination gets clobbered.
 */
int use_r10_cmp_scratch = (dst_id == 8);

/* If current address is not inside the shadow range, skip mask load/XOR entirely.
 * This is required because patched loop sites can later execute on non-secret addresses.
 */
p = emit_branch_if_not_shadow_addrreg(p, &skip_low, &skip_high,
                                      addr_reg_is_rdi,
                                      use_r10_cmp_scratch);

/* tmp = addr_base + MASK_DELTA */
if (tmp_id == 10) {
    if (addr_id == 11) {
        *p++ = 0x4D; *p++ = 0x8D; *p++ = 0x93;   /* lea r10,[r11+disp32] */
    } else {
        *p++ = 0x4C; *p++ = 0x8D; *p++ = 0x97;   /* lea r10,[rdi+disp32] */
    }
} else {
    if (addr_id == 11) {
        *p++ = 0x4D; *p++ = 0x8D; *p++ = 0x83;   /* lea r8,[r11+disp32]  */
    } else {
        *p++ = 0x4C; *p++ = 0x8D; *p++ = 0x87;   /* lea r8,[rdi+disp32]  */
    }
}
{
    int32_t d32 = (int32_t)MASK_DELTA;
    memcpy(p, &d32, 4); p += 4;
}

/* tmp = [tmp] */
if (width == 8) {
    if (tmp_id == 10) { *p++ = 0x4D; *p++ = 0x8B; *p++ = 0x12; } /* mov r10,[r10] */
    else              { *p++ = 0x4D; *p++ = 0x8B; *p++ = 0x00; } /* mov r8,[r8]   */
} else if (width == 4) {
    if (tmp_id == 10) { *p++ = 0x45; *p++ = 0x8B; *p++ = 0x12; } /* mov r10d,[r10] */
    else              { *p++ = 0x45; *p++ = 0x8B; *p++ = 0x00; } /* mov r8d,[r8]   */
} else if (width == 2) {
    if (tmp_id == 10) { *p++ = 0x66; *p++ = 0x45; *p++ = 0x8B; *p++ = 0x12; } /* mov r10w,[r10] */
    else              { *p++ = 0x66; *p++ = 0x45; *p++ = 0x8B; *p++ = 0x00; } /* mov r8w,[r8]   */
} else if (width == 1) {
    if (tmp_id == 10) { *p++ = 0x45; *p++ = 0x8A; *p++ = 0x12; } /* mov r10b,[r10] */
    else              { *p++ = 0x45; *p++ = 0x8A; *p++ = 0x00; } /* mov r8b,[r8]   */
} else {
    ABORT("emit_xor_with_mask scalar: bad width %zu", width);
}

/* dst ^= tmp */
{
    uint8_t rex = 0x40;
    if (width == 8) rex |= 0x08;
    if (tmp_id & 8) rex |= 0x04;   /* reg field = tmp */
    if (dst_id & 8) rex |= 0x01;   /* r/m field = dst */

    if (width == 2) *p++ = 0x66;
    if (rex != 0x40) *p++ = rex;
    *p++ = (width == 1) ? 0x30 : 0x31;   /* XOR r/m,reg */
    *p++ = (uint8_t)(0xC0 | ((tmp_id & 7) << 3) | (dst_id & 7));
}

/* patch the two skip branches to land here */
{
    uint8_t *end = p;
    int32_t rel;

    rel = (int32_t)(end - (skip_low + 4));
    memcpy(skip_low, &rel, 4);

    rel = (int32_t)(end - (skip_high + 4));
    memcpy(skip_high, &rel, 4);
}

return p;
    #endif
}


/* Spill/load one XMM/YMM register to/from [rsp + disp32] using VMOVDQU. */
/* vec_width = 16 for XMM, 32 for YMM.                                 */
/* load = 0 => store reg -> [rsp+disp]                                 */
/* load = 1 => load  [rsp+disp] -> reg                                 */
static inline uint8_t *emit_vmovdqu_vec_rsp_disp32(uint8_t *p,
                                                   int load,        /* 0=store, 1=load */
                                                   int vec_reg,     /* 0..15 */
                                                   size_t vec_width,/* 16 or 32 */
                                                   int32_t disp)
{
    int is_ymm = (vec_width == 32);
    if (vec_width != 16 && vec_width != 32)
        ABORT("emit_vmovdqu_vec_rsp_disp32: bad vec_width %zu", vec_width);

    *p++ = 0xC5;
    uint8_t vex2;
    if (is_ymm) {
        vex2 = (vec_reg & 8) ? 0x7E : 0xFE;   /* old working encoding pattern */
    } else {
        vex2 = (vec_reg & 8) ? 0x7A : 0xFA;
    }
    *p++ = vex2;

    *p++ = load ? 0x6F : 0x7F;                /* vmovdqu reg,mem / mem,reg */

    /* ModRM: mod=10 (disp32), reg=vec_reg&7, r/m=100 (SIB follows) */
    *p++ = (uint8_t)(0x80 | ((vec_reg & 7) << 3) | 0x04);
    *p++ = 0x24;                              /* SIB: [rsp] */

    memcpy(p, &disp, 4);
    p += 4;
    return p;
}

#if PDM_MASKING
/* Emit:
 *   if (r11 not in shadow range) skip;
 *   save rax;
 *   save ymm0, ymm1;
 *   xmm0 = tls_state
 *   xmm1 = tls_round_key
 *   xmm0 = aesenc(xmm0, xmm1)
 *   store updated state
 *   write exactly <width> fresh mask bytes to [r11 + MASK_DELTA]
 *   restore ymm1, ymm0;
 *   restore rax;
 *
 * Notes:
 * - Uses r11 as current shadow address.
 * - Uses r10 as mask-address scratch.
 * - Uses r8 inside emit_branch_if_not_secret().
 * - Uses rax as a temporary and preserves it locally.
 * - Saves/restores only ymm0/ymm1, not all vector state.
 */
static inline uint8_t *emit_refresh_mask_inline_aes(uint8_t *p, size_t width)
{
    uint8_t *skip_low = NULL, *skip_high = NULL;
    uint8_t *skip_done = NULL;

    uint64_t state_addr = (uint64_t)(uintptr_t)&tls_mask_prng_state[0];
    uint64_t key_addr   = (uint64_t)(uintptr_t)&tls_mask_prng_round_key[0];

    if (width != 1 && width != 2 && width != 4 &&
        width != 8 && width != 16 && width != 32)
        ABORT("emit_refresh_mask_inline_aes: bad width %zu", width);

    /* r11 must be inside shadow; otherwise skip */
    p = emit_branch_if_not_secret(p, &skip_low, &skip_high, 0 /* use r8 */);

    /* preserve architectural registers clobbered by this helper */
    *p++ = 0x50;                            /* push rax */
    *p++ = 0x41; *p++ = 0x50;               /* push r8  */
    *p++ = 0x41; *p++ = 0x52;               /* push r10 */

    /* sub rsp, 0x40 */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x40;

    /* save ymm0, ymm1 */
    p = emit_vmovdqu_vec_rsp_disp32(p, 0 /* store */, 0, 32, 0x00);
    p = emit_vmovdqu_vec_rsp_disp32(p, 0 /* store */, 1, 32, 0x20);

    /* r10 = r11 + MASK_DELTA */
    *p++ = 0x4D; *p++ = 0x8D; *p++ = 0x93;   /* lea r10,[r11+disp32] */
    {
        int32_t d32 = (int32_t)MASK_DELTA;
        memcpy(p, &d32, 4); p += 4;
    }

    /* rax = &tls_mask_prng_state */
    *p++ = 0x48; *p++ = 0xB8;
    memcpy(p, &state_addr, 8); p += 8;

    /* movdqu xmm0, [rax]   ; F3 0F 6F /r */
    *p++ = 0xF3; *p++ = 0x0F; *p++ = 0x6F; *p++ = 0x00;

    /* rax = &tls_mask_prng_round_key */
    *p++ = 0x48; *p++ = 0xB8;
    memcpy(p, &key_addr, 8); p += 8;

    /* movdqu xmm1, [rax] */
    *p++ = 0xF3; *p++ = 0x0F; *p++ = 0x6F; *p++ = 0x08;

    /* aesenc xmm0, xmm1    ; 66 0F 38 DC C1 */
    *p++ = 0x66; *p++ = 0x0F; *p++ = 0x38; *p++ = 0xDC; *p++ = 0xC1;

    if (width == 32) {
        /* store first 16 bytes now */
        /* movdqu [r10], xmm0 */
        *p++ = 0xF3; *p++ = 0x41; *p++ = 0x0F; *p++ = 0x7F; *p++ = 0x02;

        /* second block: aesenc xmm0, xmm1 */
        *p++ = 0x66; *p++ = 0x0F; *p++ = 0x38; *p++ = 0xDC; *p++ = 0xC1;

        /* store final state back to tls_mask_prng_state */
        *p++ = 0x48; *p++ = 0xB8;
        memcpy(p, &state_addr, 8); p += 8;
        *p++ = 0xF3; *p++ = 0x0F; *p++ = 0x7F; *p++ = 0x00;   /* movdqu [rax], xmm0 */

        /* movdqu [r10+0x10], xmm0 */
        *p++ = 0xF3; *p++ = 0x41; *p++ = 0x0F; *p++ = 0x7F; *p++ = 0x42; *p++ = 0x10;
    } else {
        /* store updated state back to tls_mask_prng_state */
        *p++ = 0x48; *p++ = 0xB8;
        memcpy(p, &state_addr, 8); p += 8;
        *p++ = 0xF3; *p++ = 0x0F; *p++ = 0x7F; *p++ = 0x00;   /* movdqu [rax], xmm0 */

        if (width == 16) {
            /* movdqu [r10], xmm0 */
            *p++ = 0xF3; *p++ = 0x41; *p++ = 0x0F; *p++ = 0x7F; *p++ = 0x02;
        } else {
            /* movq rax, xmm0   ; 66 48 0F 7E C0 */
            *p++ = 0x66; *p++ = 0x48; *p++ = 0x0F; *p++ = 0x7E; *p++ = 0xC0;

            if (width == 8) {
                /* mov [r10], rax */
                *p++ = 0x49; *p++ = 0x89; *p++ = 0x02;
            } else if (width == 4) {
                /* mov [r10], eax */
                *p++ = 0x41; *p++ = 0x89; *p++ = 0x02;
            } else if (width == 2) {
                /* mov [r10], ax */
                *p++ = 0x66; *p++ = 0x41; *p++ = 0x89; *p++ = 0x02;
            } else { /* width == 1 */
                /* mov [r10], al */
                *p++ = 0x41; *p++ = 0x88; *p++ = 0x02;
            }
        }
    }

    /* restore ymm1, ymm0 */
    p = emit_vmovdqu_vec_rsp_disp32(p, 1 /* load */, 1, 32, 0x20);
    p = emit_vmovdqu_vec_rsp_disp32(p, 1 /* load */, 0, 32, 0x00);

    /* lea rsp, [rsp + 0x40] */
    *p++ = 0x48; *p++ = 0x8D; *p++ = 0x64; *p++ = 0x24; *p++ = 0x40;

    /* restore architectural registers */
    *p++ = 0x41; *p++ = 0x5A;               /* pop r10 */
    *p++ = 0x41; *p++ = 0x58;               /* pop r8  */
    *p++ = 0x58;                            /* pop rax */

    /* jump over all of the above when r11 was not a shadow address */
    skip_done = p;
    {
        int32_t rel;

        rel = (int32_t)(skip_done - (skip_low + 4));
        memcpy(skip_low, &rel, 4);

        rel = (int32_t)(skip_done - (skip_high + 4));
        memcpy(skip_high, &rel, 4);
    }

    return p;
}
#else
static inline uint8_t *emit_refresh_mask_inline_aes(uint8_t *p, size_t width)
{
    (void)width;
    return p;
}
#endif

/* ------------------------------------------------------------------ */
/*                            Emit Load                               */
/* ------------------------------------------------------------------ */

/* ---- load value from shadow, then move it into the destination register --- */
static uint8_t *emit_load_from_shadow(uint8_t       *p,
                                      const cs_x86_op *dst,
                                      size_t          width,      /* 1/2/4/8 */
                                      uint64_t        src_abs,
                                      int             sign_extend /* 0=mov/movzx, 1=movsx */)
{


    /* ----------------  Vectorized Load  ---------------- */
    if ((dst->reg >= X86_REG_YMM0 && dst->reg <= X86_REG_YMM15) ||
        (dst->reg >= X86_REG_XMM0 && dst->reg <= X86_REG_XMM15)){

        /* movabs rdi, imm64  (shadow address in RDI) */
        if (src_abs == 0) {
                /* caller already put EA in r11 → copy to rdi */
                *p++ = 0x4C; *p++ = 0x89; *p++ = 0xDF;      /* mov rdi,r11 */
        } else {
                /* movabs rdi, imm64  (shadow address)      */
                *p++ = 0x48; *p++ = 0xBF;
                memcpy(p, &src_abs, 8);  p += 8;
        }

        /* ---- Build 2-byte VEX correctly ------------------------- */
        int  dst_id = (dst->reg >= X86_REG_YMM0 ?
                       dst->reg - X86_REG_YMM0 :
                       dst->reg - X86_REG_XMM0);            /* 0-15 */
        int  is_ymm = (dst->reg >= X86_REG_YMM0);

        *p++ = 0xC5;                            /* VEX prefix */
        uint8_t vex2 = is_ymm ? 0xFE /* L=1 */ : 0xFA /* L=0 */;
        /* clear R **only** when dst_id≥8 (high bit = 1) */
        if (dst_id & 8)  vex2 &= 0x7F;          /* R=0 for regs 8-15 */
        *p++ = vex2;

        /* vmovdqu opcode */
        *p++ = 0x6F;


        /* ModRM: 00 | (reg=dst_id&7)<<3 | rm=7 (rdi) */
        *p++ = (uint8_t)(0x00 | ((dst_id & 7) << 3) | 0x07);

        return p;                 /* done – skip scalar logic */
    }

    if (src_abs == 0 && sign_extend && width == 4 && dst->size == 8) {
        // 1) move EA from r11→rdi
        *p++ = 0x4C; *p++ = 0x89; *p++ = 0xDF;  /* mov rdi, r11 */

        // 2) emit MOVSXD <dst64>, [rdi]
        uint8_t id = rm_id(dst);
        if (id == (uint8_t)-1) ABORT("emit_load_from_shadow: bad dst reg");
        // REX.W=1; R=dst_highbit; B=0 (rdi)
        uint8_t rex = 0x48;
        if (id & 8) rex |= 0x04;               /* R=1 if dst≥8 */
        *p++ = rex;
        *p++ = 0x63;                            /* MOVSXD opcode */
        *p++ = (uint8_t)(((id & 7) << 3) | 0x07); /* ModRM: mod=00, rm=7 (rdi) */

        return p;
    }

    /* fast‑path: caller already put the address in r11            */
    if (src_abs == 0) {
            /*
            * Fast path: EA already lives in r11.
            * Copy it to rdi, then emit the exact-width load into the real dst.
            *
            * IMPORTANT:
            * For MOVZX/MOVSX, the destination width is determined by dst->size,
            * not by memory width alone.
            */
            *p++ = 0x4C; *p++ = 0x89; *p++ = 0xDF;        /* mov rdi,r11 */

            uint8_t id = rm_id(dst);
            if (id == (uint8_t)-1)
                ABORT("emit_load_from_shadow: bad dst reg");

            if (width == 1 || width == 2) {
                /*
                * MOVZX / MOVSX family.
                *
                * Cases we care about here:
                *   movzx r32, r/m8   -> 0F B6 /r
                *   movzx r32, r/m16  -> 0F B7 /r
                *   movsx r32, r/m8   -> 0F BE /r
                *   movsx r32, r/m16  -> 0F BF /r
                *   movsx r64, r/m8   -> REX.W + 0F BE /r
                *   movsx r64, r/m16  -> REX.W + 0F BF /r
                *
                */
                uint8_t rex = 0x40;

                if (sign_extend && dst->size == 8)
                    rex |= 0x08;                 /* REX.W only for sign-extend to 64-bit */

                if (id & 8)
                    rex |= 0x04;                 /* reg field high bit */

                /*
                * 0x66 is only needed for 16-bit destination forms.
                */
                if (dst->size == 2)
                    *p++ = 0x66;

                if (rex != 0x40)
                    *p++ = rex;

                *p++ = 0x0F;
                *p++ = (width == 1)
                        ? (sign_extend ? 0xBE : 0xB6)
                        : (sign_extend ? 0xBF : 0xB7);

                *p++ = 0x07 | ((id & 7) << 3);   /* reg = dst, rm = [rdi] */
                return p;
            }

            /* Plain MOV r32/r64, [rdi] */
            {
                uint8_t rex = 0x40;
                if (width == 8) rex |= 0x08;
                if (id & 8)     rex |= 0x04;
                if (rex != 0x40) *p++ = rex;

                *p++ = 0x8B;
                *p++ = 0x07 | ((id & 7) << 3);
                return p;
            }
    }

    /* ----------------  Scalar Load  ---------------- */
    /* sanity-check caller */
    if (width != 1 && width != 2 && width != 4 && width != 8 && width != 16 && width != 32)
        ABORT("emit_load_from_shadow: bad width %zu", width);
    /* bytes before disp32 for the chosen encoding */
    size_t hdr_len;
    if (width == 8) {
        hdr_len = 3;                 /* REX + 8B + ModRM */
    } else if (width == 4) {
        hdr_len = 3;                 /* MOV (8B) or MOVSXD (63) */
    } else { /* width == 1 or 2 (MOVZX / MOVSX forms) */
        hdr_len = 4;                 /* REX + 0F + B6/B7/BE/BF + ModRM */
    }
    if (llabs((int64_t)src_abs - ((int64_t)p + hdr_len + 4)) <= INT32_MAX) {
        /* ↳  Fits in 32-bit displacement → use a single RIP-relative load */
        if (sign_extend && width == 4) { /* MOVSXD r11,[rip+disp32] */
            *p++ = 0x4C; *p++ = 0x63; *p++ = 0x1D;          /* 4C 63 1D disp32 */
            uint8_t *disp_ptr = p; p += 4;
            int32_t disp32 = (int32_t)(src_abs - ((uint64_t)disp_ptr + 4));
            memcpy(disp_ptr, &disp32, 4);
        } else if (width <= 2) {
            if (sign_extend) {
                /* MOVSX r11,[rip+disp32]   (byte/word → 64b) */
                *p++ = 0x4C; *p++ = 0x0F; *p++ = (width==1 ? 0xBE : 0xBF); *p++ = 0x1D;
            } else {
                /* MOVZX r11d,[rip+disp32]  (byte/word → zero-extend) */
                *p++ = 0x44; *p++ = 0x0F; *p++ = (width==1 ? 0xB6 : 0xB7); *p++ = 0x1D;
            }
            uint8_t *disp_ptr = p; p += 4;
            int32_t disp32 = (int32_t)(src_abs - ((uint64_t)disp_ptr + 4));
            memcpy(disp_ptr, &disp32, 4);
        } else {
            /* width 4 (no sign extend) or width 8: plain MOV r11,[rip+disp32] */
            *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x1D;
            uint8_t *disp_ptr = p; p += 4;
            int32_t disp32 = (int32_t)(src_abs - ((uint64_t)disp_ptr + 4));
            memcpy(disp_ptr, &disp32, 4);
        }


    } else {
        /* ↳  Shadow address out of ±2 GiB → load it into RAX first  */
        /* scratch = R11 */
        *p++ = 0x49; *p++ = 0xBB;              /* movabs r11, imm64 */
        memcpy(p, &src_abs, 8); p += 8;

        if (width == 4) {                      /* MOV r11d,[r11] */
                *p++ = 0x45; *p++ = 0x8B; *p++ = 0x1B;
        } else if (width == 1) {
                if (sign_extend) {
                    /* MOVSX r11, byte [r11]  -> 4D 0F BE 1B */
                    *p++ = 0x4D; *p++ = 0x0F; *p++ = 0xBE; *p++ = 0x1B;
                } else {
                    /* MOVZX r11d, byte [r11] -> 45 0F B6 1B */
                    *p++ = 0x45; *p++ = 0x0F; *p++ = 0xB6; *p++ = 0x1B;
                }
        } else if (width == 2) {
                if (sign_extend) {
                    /* MOVSX r11, word [r11]  -> 4D 0F BF 1B */
                    *p++ = 0x4D; *p++ = 0x0F; *p++ = 0xBF; *p++ = 0x1B;
                } else {
                    /* MOVZX r11d, word [r11] -> 45 0F B7 1B */
                    *p++ = 0x45; *p++ = 0x0F; *p++ = 0xB7; *p++ = 0x1B;
                }

        } else {                               /* width == 8 */
                *p++ = 0x4D; *p++ = 0x8B; *p++ = 0x1B;
        }
    }

    /* --- Normalize copy width: if we loaded 1 or 2 bytes via MOVZX / MOVSX,
        r11 now holds a zero/sign-extended value in either r11d (zero) or r11 (sign).
        We must copy the *extended* size, not just the low byte/word. */
    if (width <= 2) {
        if (sign_extend) {
            /* sign-extend only to the real dest size:
               32 bit register  → copy 32 bit
               64 bit register  → copy 64 bit            */
            width = (dst->size == 8) ? 8 : 4;
        } else {
            /* MOVZX always writes 32 bits (upper half zeroed).        */
            width = 4;
        }
    }
    /* ---- copy r11 → dst (all GPRs) ---- */
    uint8_t id = rm_id(dst);
    if (id == (uint8_t)-1) ABORT("bad dst reg");

    
    /* 8A/8B /r  loads  reg ← r/m ;        */
    /* put r11 in the r/m field (= 3) and dst in the reg field.          */
    uint8_t rex = 0x40;                      /* 0100WRXB                */
    if (width == 8) rex |= 0x08;             /*      W                  */
    if (id & 8)   rex |= 0x04;               /*       R  (high bit of dst) */
    rex           |= 0x01;                   /*         B  (high bit of r11) */

    if (rex != 0x40) *p++ = rex;             /* emit REX if any bit set */
    if (width == 2)   *p++ = 0x66;           /* 16-bit operand prefix   */

    *p++ = (width == 1) ? 0x8A : 0x8B;       /* MOV  dst , r11          */
    *p++ = 0xC0 | ((id & 7) << 3) | 3;       /*           r/m = r11     */

    return p;
}


/* ------------------------------------------------------------------ */
/*                             Emit Store                             */
/* ------------------------------------------------------------------ */
static uint8_t *emit_store_to_shadow(uint8_t *p,
                                     const cs_x86_op *src,  /* source register */
                                     size_t width,
                                     uint64_t dst_abs)
{
    /* fast-path: caller left the shadow address in R11.
    We canonicalize the memory base into RDI for both vector and scalar stores. */
    if (dst_abs == 0) {
        /* mov rdi, r11  (two‑byte encoding: 4C 89 DF) */
        *p++ = 0x4C; *p++ = 0x89; *p++ = 0xDF;
        goto have_ptr_in_r11;
    }

    /* rdi = shadow_addr                                           */
    *p++ = 0x48; *p++ = 0xBF;
    memcpy(p,&dst_abs,8); p+=8;

    /* ----- emit the width-specific store ----- */
have_ptr_in_r11:
    if (width == 32 || width == 16) {
        int  src_id = (width==32 ?
                       src->reg - X86_REG_YMM0 :
                       src->reg - X86_REG_XMM0);
        int  is_ymm = (width == 32);

        *p++ = 0xC5;
        uint8_t vex2 = is_ymm ? 0xFE : 0xFA;
        if (src_id & 8)  vex2 &= 0x7F;           /* clear R only for 8-15 */
        *p++ = vex2;

        *p++ = 0x7F;                              /* vmovdqu store */
        *p++ = (uint8_t)( ((src_id & 7) << 3) | 0x07 );
    } else {
        uint8_t id = rm_id(src);          /* scalar: need GPR id   */
        if (id == (uint8_t)-1)
            ABORT("bad scalar src reg (%d)", src->reg);

        if (width == 8) {
            uint8_t rex = 0x48;                 /* REX.W */
            if (id & 8) rex |= 0x04;            /* REX.R if src is r8..r15 */
            *p++ = rex;
            *p++ = 0x89;                        /* mov [rdi], src */
            *p++ = 0x07 | ((id & 7) << 3);      /* ModRM */
        }
        else if (width == 4) {
            uint8_t rex = 0x40;
            if (id & 8) rex |= 0x04;
            if (rex != 0x40) *p++ = rex;
            *p++ = 0x89;                        /* mov [rdi], src */
            *p++ = 0x07 | ((id & 7) << 3);      /* ModRM */
        }
        else if (width == 2) {
            *p++ = 0x66;                        /* operand-size prefix must come before REX */
            uint8_t rex = 0x40;
            if (id & 8) rex |= 0x04;
            if (rex != 0x40) *p++ = rex;
            *p++ = 0x89;                        /* mov [rdi], src */
            *p++ = 0x07 | ((id & 7) << 3);      /* ModRM */
        }
        else if (width == 1) {
            uint8_t rex = 0x40;                 /* always emit for byte regs like sil/dil/r8b... */
            if (id & 8) rex |= 0x04;
            *p++ = rex;
            *p++ = 0x88;                        /* mov byte [rdi], src */
            *p++ = 0x07 | ((id & 7) << 3);      /* ModRM */
        }
        else {
            ABORT("emit_store_to_shadow: bad scalar width %zu", width);
        }
    }

    return p;
}

/* Store XMM/YMM source to shadow without modifying the architectural source.
 * Uses vector temp register 15 (xmm15/ymm15), saved/restored on the stack.
 * Uses r11/rdi the same way as emit_store_to_shadow().
 */
static inline uint8_t *emit_store_vector_preserve_src(uint8_t *p,
                                                      const cs_x86_op *src,
                                                      size_t width,
                                                      uint64_t dst_abs)
{
    if (width != 16 && width != 32)
        ABORT("emit_store_vector_preserve_src: bad width %zu", width);
    if (src->type != X86_OP_REG)
        ABORT("emit_store_vector_preserve_src: src not reg");

    /* canonicalize destination address exactly like emit_store_to_shadow() */
    if (dst_abs == 0) {
        *p++ = 0x4C; *p++ = 0x89; *p++ = 0xDF;   /* mov rdi, r11 */
    } else {
        *p++ = 0x48; *p++ = 0xBF;                /* movabs rdi, imm64 */
        memcpy(p, &dst_abs, 8); p += 8;
    }

    /* reserve 0x40:
     * [rsp+0x00] = saved temp vec15
     * [rsp+0x20] = copied source
     */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x40;   /* sub rsp, 0x40 */

    /* save temp vec15 */
    p = emit_vmovdqu_vec_rsp_disp32(p, 0 /* store */, 15, width, 0x00);

    /* spill source to stack */
    {
        int src_id;
        if (width == 32) {
            if (src->reg < X86_REG_YMM0 || src->reg > X86_REG_YMM15)
                ABORT("emit_store_vector_preserve_src: expected YMM src");
            src_id = src->reg - X86_REG_YMM0;
        } else {
            if (src->reg < X86_REG_XMM0 || src->reg > X86_REG_XMM15)
                ABORT("emit_store_vector_preserve_src: expected XMM src");
            src_id = src->reg - X86_REG_XMM0;
        }
        p = emit_vmovdqu_vec_rsp_disp32(p, 0 /* store */, src_id, width, 0x20);
    }

    /* load source copy into temp vec15 */
    p = emit_vmovdqu_vec_rsp_disp32(p, 1 /* load */, 15, width, 0x20);

    /* temp ^= mask */
    cs_x86_op tmpop = {
        .type = X86_OP_REG,
        .reg  = (width == 32) ? X86_REG_YMM15 : X86_REG_XMM15,
        .size = width
    };
    p = emit_xor_with_mask(p, &tmpop, width, (width == 32) ? 2 : 1);

    /* store temp to shadow */
    p = emit_store_to_shadow(p, &tmpop, width, 0);

    /* restore temp vec15 */
    p = emit_vmovdqu_vec_rsp_disp32(p, 1 /* load */, 15, width, 0x00);

    /* release stack */
    *p++ = 0x48; *p++ = 0x8D; *p++ = 0x64; *p++ = 0x24; *p++ = 0x40;  /* lea rsp,[rsp+0x40] */

    return p;
}

/* Load into r10 from [r11] without clobbering rdi */
static inline uint8_t *emit_load_r10_from_r11(uint8_t *p, size_t width)
{
    if (width == 8) { *p++=0x4D; *p++=0x8B; *p++=0x13; }          /* mov r10,  [r11] */
    else if (width == 4) { *p++=0x45; *p++=0x8B; *p++=0x13; }     /* mov r10d, [r11] */
    else if (width == 2) { *p++=0x66; *p++=0x45; *p++=0x8B; *p++=0x13; } /* mov r10w,[r11] */
    else if (width == 1) { *p++=0x45; *p++=0x8A; *p++=0x13; }     /* mov r10b, [r11] */
    else ABORT("bad width in emit_load_r10_from_r11: %zu", width);
    return p;
}

static inline uint8_t *emit_movq_xmm_from_r10(uint8_t *p, const cs_x86_op *dst)
{
    int dst_id = xmm_id(dst->reg);
    if (dst_id < 0)
        ABORT("emit_movq_xmm_from_r10: dst is not XMM");

    /*
     * movq xmm, r/m64  == 66 REX.W 0F 6E /r
     * src is r10 => rm = 010, requires REX.B=1
     * dst xmm goes in ModRM.reg, so XMM8-15 needs REX.R=1
     */
    *p++ = 0x66;

    uint8_t rex = 0x49;              /* REX.W=1, REX.B=1 (r10) */
    if (dst_id & 8) rex |= 0x04;     /* REX.R for xmm8-15 */
    *p++ = rex;

    *p++ = 0x0F;
    *p++ = 0x6E;
    *p++ = (uint8_t)(0xC0 | ((dst_id & 7) << 3) | 0x02);  /* mod=11, rm=r10 */

    return p;
}

static inline uint8_t *emit_movq_r10_from_xmm(uint8_t *p, const cs_x86_op *src)
{
    int src_id = xmm_id(src->reg);
    if (src_id < 0)
        ABORT("emit_movq_r10_from_xmm: src is not XMM");

    /*
     * movq r/m64, xmm  == 66 REX.W 0F 7E /r
     * dst is r10 => rm = 010, requires REX.B=1
     * src xmm goes in ModRM.reg, so XMM8-15 needs REX.R=1
     */
    *p++ = 0x66;

    uint8_t rex = 0x49;              /* REX.W=1, REX.B=1 (r10) */
    if (src_id & 8) rex |= 0x04;     /* REX.R for xmm8-15 */
    *p++ = rex;

    *p++ = 0x0F;
    *p++ = 0x7E;
    *p++ = (uint8_t)(0xC0 | ((src_id & 7) << 3) | 0x02);  /* mod=11, rm=r10 */

    return p;
}

/* Store from r10 into [r11] without clobbering rdi */
static inline uint8_t *emit_store_r10_to_r11(uint8_t *p, size_t width)
{
    if (width == 8) { *p++=0x4D; *p++=0x89; *p++=0x13; }          /* mov [r11], r10 */
    else if (width == 4) { *p++=0x45; *p++=0x89; *p++=0x13; }     /* mov [r11], r10d */
    else if (width == 2) { *p++=0x66; *p++=0x45; *p++=0x89; *p++=0x13; } /* mov [r11], r10w */
    else if (width == 1) { *p++=0x45; *p++=0x88; *p++=0x13; }     /* mov [r11], r10b */
    else ABORT("bad width in emit_store_r10_to_r11: %zu", width);
    return p;
}

static inline uint8_t *emit_store_rax_to_r11(uint8_t *p, size_t width)
{
    if (width == 8) {
        *p++ = 0x49; *p++ = 0x89; *p++ = 0x03;              /* mov [r11], rax */
    } else if (width == 4) {
        *p++ = 0x41; *p++ = 0x89; *p++ = 0x03;              /* mov [r11], eax */
    } else if (width == 2) {
        *p++ = 0x66; *p++ = 0x41; *p++ = 0x89; *p++ = 0x03; /* mov [r11], ax  */
    } else if (width == 1) {
        *p++ = 0x41; *p++ = 0x88; *p++ = 0x03;              /* mov [r11], al  */
    } else {
        ABORT("emit_store_rax_to_r11: bad width %zu", width);
    }
    return p;
}

static inline uint8_t *emit_store_rax_to_rdi(uint8_t *p, size_t width)
{
    if (width == 8) {
        *p++ = 0x48; *p++ = 0x89; *p++ = 0x07;              /* mov [rdi], rax */
    } else if (width == 4) {
        *p++ = 0x89; *p++ = 0x07;                           /* mov [rdi], eax */
    } else if (width == 2) {
        *p++ = 0x66; *p++ = 0x89; *p++ = 0x07;              /* mov [rdi], ax  */
    } else if (width == 1) {
        *p++ = 0x88; *p++ = 0x07;                           /* mov [rdi], al  */
    } else {
        ABORT("emit_store_rax_to_rdi: bad width %zu", width);
    }
    return p;
}

static inline uint8_t *emit_mask_and_store_rax_to_rdi(uint8_t *p, size_t width)
{
#if !PDM_MASKING
    return emit_store_rax_to_rdi(p, width);
#else
    uint8_t *skip_low = NULL, *skip_high = NULL;

    /* If RDI is not inside shadow, skip the WHOLE mask+store block. */
    p = emit_branch_if_not_shadow_addrreg(p, &skip_low, &skip_high,
                                        1 /* compare RDI */,
                                        0 /* use r8 scratch */);

    /* r10 = rdi + MASK_DELTA */
    *p++ = 0x4C; *p++ = 0x8D; *p++ = 0x97;   /* lea r10,[rdi+disp32] */
    {
        int32_t d32 = (int32_t)MASK_DELTA;
        memcpy(p, &d32, 4); p += 4;
    }

    /* r10 = [r10] */
    if (width == 8) {
        *p++ = 0x4D; *p++ = 0x8B; *p++ = 0x12;                    /* mov r10,  [r10] */
    } else if (width == 4) {
        *p++ = 0x45; *p++ = 0x8B; *p++ = 0x12;                    /* mov r10d, [r10] */
    } else if (width == 2) {
        *p++ = 0x66; *p++ = 0x45; *p++ = 0x8B; *p++ = 0x12;      /* mov r10w, [r10] */
    } else if (width == 1) {
        *p++ = 0x45; *p++ = 0x8A; *p++ = 0x12;                    /* mov r10b, [r10] */
    } else {
        ABORT("emit_mask_and_store_rax_to_rdi: bad width %zu", width);
    }

    /* rax ^= r10 */
    if (width == 8) {
        *p++ = 0x4C; *p++ = 0x31; *p++ = 0xD0;                    /* xor rax,  r10 */
    } else if (width == 4) {
        *p++ = 0x44; *p++ = 0x31; *p++ = 0xD0;                    /* xor eax,  r10d */
    } else if (width == 2) {
        *p++ = 0x66; *p++ = 0x44; *p++ = 0x31; *p++ = 0xD0;      /* xor ax,   r10w */
    } else if (width == 1) {
        *p++ = 0x44; *p++ = 0x30; *p++ = 0xD0;                    /* xor al,   r10b */
    }

    /* store [rdi] = rax/eax/ax/al */
    p = emit_store_rax_to_rdi(p, width);

    /* Patch the two skip branches to jump past BOTH xor and store. */
    {
        uint8_t *end = p;
        int32_t rel;

        rel = (int32_t)(end - (skip_low + 4));
        memcpy(skip_low, &rel, 4);

        rel = (int32_t)(end - (skip_high + 4));
        memcpy(skip_high, &rel, 4);
    }

    return p;
#endif
}

/* Copy src GPR into r10/r10d/r10w/r10b without modifying src. */
static inline uint8_t *emit_mov_r10_from_reg(uint8_t *p,
                                             const cs_x86_op *src,
                                             size_t width)
{
    int src_id = rm_id(src);
    if (src_id < 0) ABORT("emit_mov_r10_from_reg: bad src reg");
    if (width != 1 && width != 2 && width != 4 && width != 8)
        ABORT("emit_mov_r10_from_reg: bad width %zu", width);

    if (width == 2) *p++ = 0x66;

    /* dest = r10 => REX.R=1 because reg field is r10 (010 with high bit set) */
    uint8_t rex = 0x44;               /* 0100 0100 : REX.R */
    if (width == 8) rex |= 0x08;      /* REX.W */
    if (src_id & 8) rex |= 0x01;      /* REX.B for src in r/m */
    *p++ = rex;

    *p++ = (width == 1) ? 0x8A : 0x8B;   /* mov r10{b/w/d/q}, src */
    *p++ = (uint8_t)(0xC0 | ((2 & 7) << 3) | (src_id & 7));  /* reg=r10, rm=src */

    return p;
}

static inline uint8_t *emit_push_reg64(uint8_t *p, x86_reg reg)
{
    switch (reg) {
    case X86_REG_RAX:
    case X86_REG_EAX:
        *p++ = 0x50;                           /* push rax */
        break;
    case X86_REG_RDI:
    case X86_REG_EDI:
        *p++ = 0x57;                           /* push rdi */
        break;
    case X86_REG_R10:
    case X86_REG_R10D:
        *p++ = 0x41; *p++ = 0x52;             /* push r10 */
        break;
    case X86_REG_R11:
    case X86_REG_R11D:
        *p++ = 0x41; *p++ = 0x53;             /* push r11 */
        break;
    default:
        ABORT("emit_push_reg64: unsupported reg %d", reg);
    }
    return p;
}

static inline uint8_t *emit_pop_reg64(uint8_t *p, x86_reg reg)
{
    switch (reg) {
    case X86_REG_RAX:
    case X86_REG_EAX:
        *p++ = 0x58;                           /* pop rax */
        break;
    case X86_REG_RDI:
    case X86_REG_EDI:
        *p++ = 0x5F;                           /* pop rdi */
        break;
    case X86_REG_R10:
    case X86_REG_R10D:
        *p++ = 0x41; *p++ = 0x5A;             /* pop r10 */
        break;
    case X86_REG_R11:
    case X86_REG_R11D:
        *p++ = 0x41; *p++ = 0x5B;             /* pop r11 */
        break;
    default:
        ABORT("emit_pop_reg64: unsupported reg %d", reg);
    }
    return p;
}

/* dst ^= rax/eax/ax/al */
static inline uint8_t *emit_xor_dst_with_rax(uint8_t *p, x86_reg dst_reg, size_t width)
{
    cs_x86_op dst = {
        .type = X86_OP_REG,
        .reg  = dst_reg,
        .size = width
    };

    int dst_id = rm_id(&dst);
    if (dst_id < 0)
        ABORT("emit_xor_dst_with_rax: bad dst reg");

    if (width != 1 && width != 2 && width != 4 && width != 8)
        ABORT("emit_xor_dst_with_rax: bad width %zu", width);

    if (width == 2) *p++ = 0x66;

    uint8_t rex = 0x40;
    if (width == 8) rex |= 0x08;          /* REX.W */
    if (dst_id & 8) rex |= 0x01;          /* dst in r/m field */
    if (rex != 0x40) *p++ = rex;

    *p++ = (width == 1) ? 0x30 : 0x31;    /* xor r/m, reg */
    *p++ = (uint8_t)(0xC0 | (0 << 3) | (dst_id & 7));   /* reg = rax/eax/ax/al */

    return p;
}

/* Safe slow-path for XOR dst,[mem] when dst aliases our scratch set. */
static inline uint8_t *emit_xor_reg_mem_preserve_scratch(uint8_t *p,
                                                         const cs_x86_op *dst,
                                                         const cs_x86_op *mop,
                                                         uint64_t ins_addr,
                                                         size_t insn_size,
                                                         size_t width)
{
    cs_x86_op aop = {
        .type = X86_OP_REG,
        .reg  = (width == 1) ? X86_REG_AL  :
                (width == 2) ? X86_REG_AX  :
                (width == 4) ? X86_REG_EAX : X86_REG_RAX,
        .size = width
    };

    /* Save caller RAX and original dst value */
    p = emit_push_reg64(p, X86_REG_RAX);
    p = emit_push_reg64(p, dst->reg);

    /* r11 = shadow address */
    p = emit_lea_r11(p, mop, ins_addr, insn_size);
    p = emit_add_r11_imm(p, SHADOW_DELTA);

    /* load plaintext into A-register and unmask it */
    p = emit_load_from_shadow(p, &aop, width, 0, 0);
    p = emit_xor_with_mask(p, &aop, width, 0);

    /* restore original dst, then dst ^= a-reg */
    p = emit_pop_reg64(p, dst->reg);
    p = emit_xor_dst_with_rax(p, dst->reg, width);

    /* restore caller RAX */
    p = emit_pop_reg64(p, X86_REG_RAX);

    return p;
}

static inline uint8_t *emit_mov_reg_mem_preserve_scratch(uint8_t *p,
                                                         const cs_x86_op *dst,
                                                         const cs_x86_op *mop,
                                                         uint64_t ins_addr,
                                                         size_t insn_size,
                                                         size_t width,
                                                         int sign_extend)
{
    cs_x86_op aop = {
        .type = X86_OP_REG,
        .reg  = (width == 1) ? X86_REG_AL  :
                (width == 2) ? X86_REG_AX  :
                (width == 4) ? X86_REG_EAX : X86_REG_RAX,
        .size = width
    };

    int dst_id;

    if (width != 1 && width != 2 && width != 4 && width != 8)
        ABORT("emit_mov_reg_mem_preserve_scratch: bad width %zu", width);

    dst_id = rm_id(dst);
    if (dst_id < 0)
        ABORT("emit_mov_reg_mem_preserve_scratch: bad dst reg");

    /* save caller RAX */
    p = emit_push_reg64(p, X86_REG_RAX);

    /* r11 = shadow address */
    p = emit_lea_r11(p, mop, ins_addr, insn_size);
    p = emit_add_r11_imm(p, SHADOW_DELTA);

    /* load masked value into A-reg and unmask there */
    p = emit_load_from_shadow(p, &aop, width, 0, sign_extend);
    p = emit_xor_with_mask(p, &aop, width, 0);

    /* move A-reg -> real destination */
    if (width == 2) *p++ = 0x66;

    {
        uint8_t rex = 0x40;
        if (width == 8) rex |= 0x08;          /* W */
        if (dst_id & 8) rex |= 0x01;          /* r/m = dst */
        if (rex != 0x40) *p++ = rex;

        *p++ = (width == 1) ? 0x88 : 0x89;    /* mov r/m, reg */
        *p++ = (uint8_t)(0xC0 | ((0 & 7) << 3) | (dst_id & 7)); /* reg = A */
    }

    /* restore caller RAX */
    p = emit_pop_reg64(p, X86_REG_RAX);

    return p;
}

/* Conditionally redirect r11 from secret -> shadow. (Uses ONLY r8 as temp) */
static inline uint8_t *emit_maybe_shadow_r11(uint8_t *t,
                                             uint64_t secret_base,
                                             uint64_t secret_end)
{
    /* movabs r8, secret_base */
    *t++ = 0x49; *t++ = 0xB8;
    memcpy(t, &secret_base, 8); t += 8;

    /* cmp r11, r8 */
    *t++ = 0x4D; *t++ = 0x39; *t++ = 0xC3;

    /* jb skip */
    *t++ = 0x0F; *t++ = 0x82;
    uint8_t *jb_skip = t; t += 4;

    /* movabs r8, secret_end */
    *t++ = 0x49; *t++ = 0xB8;
    memcpy(t, &secret_end, 8); t += 8;

    /* cmp r11, r8 */
    *t++ = 0x4D; *t++ = 0x39; *t++ = 0xC3;

    /* jae skip */
    *t++ = 0x0F; *t++ = 0x83;
    uint8_t *jae_skip = t; t += 4;

    /* inside secret: add r11, SHADOW_DELTA */
    t = emit_add_r11_imm(t, SHADOW_DELTA);

    /* patch both jumps to here */
    {
        int32_t rel = (int32_t)(t - (jb_skip + 4));
        memcpy(jb_skip, &rel, 4);
    }
    {
        int32_t rel = (int32_t)(t - (jae_skip + 4));
        memcpy(jae_skip, &rel, 4);
    }

    return t;
}

static inline uint8_t *emit_recompute_shadow_r11(uint8_t *p,
                                                 const cs_x86_op *memop,
                                                 uint64_t ins_addr,
                                                 size_t insn_size)
{
    p = emit_lea_r11(p, memop, ins_addr, insn_size);
    p = emit_add_r11_imm(p, SHADOW_DELTA);
    return p;
}

static inline int rep_kind(const cs_insn *ins)
{
    const uint8_t *p = ins->detail->x86.prefix;
    for (int i = 0; i < 4; i++) {
        if (p[i] == 0xF3) return 1;   /* REP / REPE */
        if (p[i] == 0xF2) return 2;   /* REPNE      */
    }
    return 0;
}

static inline int preserve_incoming_flags_for_translated_insn(const cs_insn *ins)
{
    switch (ins->id) {
        /*
         * These define outgoing flags and do NOT consume incoming flags,
         * so generic pushfq/popfq around the whole translation is wrong.
         */
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_XOR:
        case X86_INS_OR:
        case X86_INS_AND:
        case X86_INS_CMP:
        case X86_INS_TEST:
        case X86_INS_INC:
        case X86_INS_DEC:
            return 0;

        /*
         * SBB is special: it consumes incoming CF and defines outgoing flags.
         * We handle it manually inside the SBB translation paths with:
         *   pushfq ... helper code ... popfq ... sbb
         * and for RMW:
         *   ... sbb ; pushfq ... post-store helpers ... popfq
         */
        case X86_INS_SBB:
            return 0;

        default:
            return 1;
    }
}

/*──────────────────────────────────────────────────────────────────*/
/*  Emit a tiny loop that replaces REP MOVS/STOS inside a tramp  */
/*     – supports width 1/2/4/8, DF = 0 (CLD) only                 */
/*     – keeps RCX semantics (ends with RCX = 0)                   */
/*     – updates RSI/RDI exactly like the real CPU                 */
/*     – uses R10 as data reg, R11 as addr scratch                 */
/*──────────────────────────────────────────────────────────────────*/
static uint8_t * emit_rep_movs_stos(uint8_t *t, int is_movs, size_t width)
{
    if (!secret || !secret_len) ABORT("emit_rep_movs_stos: secret not initialized");
    uint64_t secret_base_abs = (uint64_t)secret;
    uint64_t secret_end_abs  = secret_base_abs + secret_len;

    /* Reject DF=1. This software loop currently implements only forward strings. */
    /* save caller rax locally */
    *t++ = 0x50;                                      /* push rax            */
    *t++ = 0x9C;                                      /* pushfq              */
    *t++ = 0x58;                                      /* pop rax             */
    *t++ = 0xF6; *t++ = 0xC4; *t++ = 0x04;           /* test ah, 0x04       */
    *t++ = 0x58;                                      /* pop rax             */
    *t++ = 0x0F; *t++ = 0x85;                         /* jnz unsupported     */
    uint8_t *df_bad = t; t += 4;

    /* --------  .Ltest:  test rcx,rcx ;  jz .Lend  -------- */
    *t++ = 0x48; *t++ = 0x85; *t++ = 0xC9;           /* test rcx, rcx      */
    *t++ = 0x0F; *t++ = 0x84;                        /* jz  rel32 (.Lend)  */
    uint8_t *jmp_to_end = t;  t += 4;                /* <-- patch later    */

    /* ----------------  .Lloop  ---------------- */
    uint8_t *lbl_loop = t;

    if (is_movs) {
        /* ---- SRC FIRST ---- */
        *t++ = 0x4C; *t++ = 0x8D; *t++ = 0x1E;                  /* lea r11,[rsi] */
        t = emit_maybe_shadow_r11(t, secret_base_abs, secret_end_abs);
        /* r11 now = effective src (possibly in shadow); r8 is scratch/garbage */

        cs_x86_op valreg = (cs_x86_op){
            .type = X86_OP_REG,
            .reg  = (width==1)?X86_REG_R10B :
                    (width==2)?X86_REG_R10W :
                    (width==4)?X86_REG_R10D : X86_REG_R10,
            .size = width
        };

        t = emit_load_r10_from_r11(t, width);         /* r10 = [src] (maybe masked) */
        t = emit_xor_with_mask(t, &valreg, width, 0); /* unmask -> plaintext */

        /* ---- DEST SECOND ---- */
        *t++ = 0x4C; *t++ = 0x8D; *t++ = 0x1F;                  /* lea r11,[rdi] */
        t = emit_maybe_shadow_r11(t, secret_base_abs, secret_end_abs);
        /* r11 now = effective dest (possibly shadow); r8 again scratch */
        t = emit_refresh_mask_inline_aes(t, width);

        // /* recompute dest shadow address after refresh */
        // *t++ = 0x4C; *t++ = 0x8D; *t++ = 0x1F;                  /* lea r11,[rdi] */
        // t = emit_maybe_shadow_r11(t, secret_base_abs, secret_end_abs);

        t = emit_xor_with_mask(t, &valreg, width, 0);/* re-mask for shadow store */
        t = emit_store_r10_to_r11(t, width);         /* [dest] = r10 */
    } else {
        /* ---- DEST first ---- */
        *t++ = 0x4C; *t++ = 0x8D; *t++ = 0x1F;                  /* lea r11,[rdi] */
        t = emit_maybe_shadow_r11(t, secret_base_abs, secret_end_abs);
        t = emit_refresh_mask_inline_aes(t, width);

        // /* recompute dest shadow address after refresh */
        // *t++ = 0x4C; *t++ = 0x8D; *t++ = 0x1F;                  /* lea r11,[rdi] */
        // t = emit_maybe_shadow_r11(t, secret_base_abs, secret_end_abs);

        /* ---- copy RAX -> R10 AFTER helper ---- */
        if (width == 8)      { *t++=0x49; *t++=0x89; *t++=0xC2; }            /* mov r10,  rax */
        else if (width == 4) { *t++=0x41; *t++=0x89; *t++=0xC2; }            /* mov r10d, eax */
        else if (width == 2) { *t++=0x66; *t++=0x41; *t++=0x89; *t++=0xC2; } /* mov r10w, ax  */
        else if (width == 1) { *t++=0x41; *t++=0x88; *t++=0xC2; }            /* mov r10b, al  */
        else ABORT("rep stos bad width %zu", width);

        cs_x86_op r10reg = (cs_x86_op){ .type = X86_OP_REG,
            .reg  = (width==1)?X86_REG_R10B : (width==2)?X86_REG_R10W : (width==4)?X86_REG_R10D : X86_REG_R10,
            .size = width };

        t = emit_xor_with_mask(t, &r10reg, width, 0);            /* mask plaintext */
        t = emit_store_r10_to_r11(t, width);                     /* [dest] = masked */
    }


    /* --------------------  ++RSI / ++RDI  (DF=0 only)  ------------------- */
    /* --------  ++RSI (MOVS only), ++RDI (MOVS+STOS)  (DF=0 only)  -------- */
    if (is_movs) {
        if (width == 1) { *t++ = 0x48; *t++ = 0xFF; *t++ = 0xC6; }       /* inc rsi */
        else if (width == 2) { *t++ = 0x48; *t++ = 0x83; *t++ = 0xC6; *t++ = 0x02; }
        else if (width == 4) { *t++ = 0x48; *t++ = 0x83; *t++ = 0xC6; *t++ = 0x04; }
        else if (width == 8) { *t++ = 0x48; *t++ = 0x83; *t++ = 0xC6; *t++ = 0x08; }
    }

    if (width == 1) { *t++ = 0x48; *t++ = 0xFF; *t++ = 0xC7; }       /* inc rdi */
    if (width == 2) { *t++ = 0x48; *t++ = 0x83; *t++ = 0xC7; *t++ = 0x02; }
    if (width == 4) { *t++ = 0x48; *t++ = 0x83; *t++ = 0xC7; *t++ = 0x04; }
    if (width == 8) { *t++ = 0x48; *t++ = 0x83; *t++ = 0xC7; *t++ = 0x08; }

    /* ------  RCX-- ;  jnz .Lloop  ------ */
    *t++ = 0x48; *t++ = 0xFF; *t++ = 0xC9;                      /* dec rcx     */
    *t++ = 0x0F; *t++ = 0x85;                                    /* jnz rel32   */
    {
        int32_t rel = (int32_t)(lbl_loop - (t + 4));
        memcpy(t, &rel, 4);  t += 4;
    }

    /* -------- normal end label -------- */
    uint8_t *normal_end = t;

    /* patch JZ rcx==0 to normal end */
    {
        int32_t rel = (int32_t)(normal_end - (jmp_to_end + 4));
        memcpy(jmp_to_end, &rel, 4);
    }

    /* jump over the unsupported stub */
    *t++ = 0xEB;                  /* jmp short done */
    uint8_t *skip_unsupported = t; 
    *t++ = 0x00;                  /* patched below */

    /* -------- unsupported DF=1 label -------- */
    uint8_t *unsupported_df = t;
    *t++ = 0xCC;                  /* int3 */

    /* patch DF check to unsupported_df */
    {
        int32_t rel = (int32_t)(unsupported_df - (df_bad + 4));
        memcpy(df_bad, &rel, 4);
    }

    /* -------- done label -------- */
    uint8_t *done = t;

    /* patch jump over unsupported stub */
    {
        int8_t rel8 = (int8_t)(done - (skip_unsupported + 1));
        memcpy(skip_unsupported, &rel8, 1);
    }

    return t;
}


static uint8_t* emit_test_reg_imm(uint8_t *p,
                                  uint8_t reg,
                                  size_t  width,   /* BYTES: 1/2/4/8 */
                                  uint64_t imm)
{
    if (width != 1 && width != 2 && width != 4 && width != 8)
        ABORT("emit_test_reg_imm: bad width %zu", width);

    if (width == 1) {
        uint8_t rex = 0x40 | ((reg & 8) ? 0x01 : 0);   /* REX.B for r8-r15 */
        if (rex != 0x40) *p++ = rex;

        *p++ = 0xF6;                     /* TEST r/m8, imm8 */
        *p++ = 0xC0 | (reg & 7);         /* mod=11, /0, r/m=reg */
        *p++ = (uint8_t)imm;
        return p;
    }

    if (width == 2) *p++ = 0x66;        /* 16-bit operand-size prefix */

    {
        uint8_t rex = 0x40
                    | ((width == 8) ? 0x08 : 0)   /* REX.W for 64-bit */
                    | ((reg & 8) ? 0x01 : 0);     /* REX.B for r8-r15 */
        if (rex != 0x40) *p++ = rex;
    }

    *p++ = 0xF7;                         /* TEST r/m16/32/64, imm16/32 */
    *p++ = 0xC0 | (reg & 7);             /* mod=11, /0, r/m=reg */

    if (width == 2) {
        uint16_t v = (uint16_t)imm;
        memcpy(p, &v, 2); p += 2;
    } else {
        uint32_t v = (uint32_t)imm;      /* 64-bit form uses sign-extended imm32 */
        memcpy(p, &v, 4); p += 4;
    }

    return p;
}

static uint8_t *emit_group1_r10_imm(uint8_t *p,
                                    uint8_t group_ext,   /* 1=OR, 4=AND, 6=XOR */
                                    size_t  width,
                                    uint64_t imm)
{
    if (width != 1 && width != 2 && width != 4 && width != 8)
        ABORT("emit_group1_r10_imm: bad width %zu", width);

    if (width == 2) *p++ = 0x66;

    /* r10 is a high register => need REX.B */
    uint8_t rex = 0x41;
    if (width == 8) rex |= 0x08;   /* REX.W */
    *p++ = rex;

    if (width == 1) {
        *p++ = 0x80;   /* 80 /digit ib */
        *p++ = (uint8_t)(0xC0 | ((group_ext & 7) << 3) | 0x02);  /* mod=11, r/m=r10b */
        *p++ = (uint8_t)imm;
        return p;
    }

    {
        int64_t simm = (int64_t)imm;
        if (simm >= -128 && simm <= 127) {
            *p++ = 0x83;   /* 83 /digit ib (sign-extended) */
            *p++ = (uint8_t)(0xC0 | ((group_ext & 7) << 3) | 0x02);  /* r10 */
            *p++ = (uint8_t)imm;
        } else {
            *p++ = 0x81;   /* 81 /digit iw/id */
            *p++ = (uint8_t)(0xC0 | ((group_ext & 7) << 3) | 0x02);  /* r10 */
            if (width == 2) {
                uint16_t v = (uint16_t)imm;
                memcpy(p, &v, 2); p += 2;
            } else {
                uint32_t v = (uint32_t)imm;
                memcpy(p, &v, 4); p += 4;
            }
        }
    }

    return p;
}

static uint8_t *emit_binop_r10_reg(uint8_t *p,
                                   uint8_t base_opcode,   /* 0x00 ADD, 0x30 XOR */
                                   const cs_x86_op *src,
                                   size_t width)
{
    int src_id = rm_id(src);
    if (src_id < 0) ABORT("emit_binop_r10_reg: bad src reg");
    if (width != 1 && width != 2 && width != 4 && width != 8)
        ABORT("emit_binop_r10_reg: bad width %zu", width);

    if (width == 2) *p++ = 0x66;

    /* r/m = r10 => REX.B=1 ; reg = src => REX.R if needed */
    uint8_t rex = 0x41;
    if (width == 8) rex |= 0x08;   /* REX.W */
    if (src_id & 8) rex |= 0x04;   /* REX.R */
    *p++ = rex;

    *p++ = (width == 1) ? base_opcode : (uint8_t)(base_opcode + 1);
    *p++ = (uint8_t)(0xC0 | ((src_id & 7) << 3) | 0x02);  /* mod=11, r/m=r10 */

    return p;
}

static uint8_t *emit_sbb_r10_reg(uint8_t *p,
                                 const cs_x86_op *src,
                                 size_t width)
{
    int src_id = rm_id(src);
    if (src_id < 0) ABORT("emit_sbb_r10_reg: bad src reg");
    if (width != 1 && width != 2 && width != 4 && width != 8)
        ABORT("emit_sbb_r10_reg: bad width %zu", width);

    if (width == 2) *p++ = 0x66;

    /* r/m = r10 => REX.B=1 ; reg = src => REX.R if needed */
    uint8_t rex = 0x41;
    if (width == 8) rex |= 0x08;   /* REX.W */
    if (src_id & 8) rex |= 0x04;   /* REX.R */
    *p++ = rex;

    *p++ = (width == 1) ? 0x18 : 0x19;   /* sbb r/m, reg */
    *p++ = (uint8_t)(0xC0 | ((src_id & 7) << 3) | 0x02);  /* mod=11, r/m=r10 */

    return p;
}

static uint8_t *emit_mul_rax_r10(uint8_t *p, size_t width)
{
    if (width != 1 && width != 2 && width != 4 && width != 8)
        ABORT("emit_mul_rax_r10: bad width %zu", width);

    if (width == 2) *p++ = 0x66;

    if (width == 1) {
        /* mul r10b  => F6 /4 with r/m = r10b */
        *p++ = 0x41;                  /* REX.B */
        *p++ = 0xF6;
        *p++ = 0xE2;                  /* mod=11, /4, r/m=010 (r10b) */
        return p;
    }

    {
        uint8_t rex = 0x41;           /* REX.B => r/m is r10 */
        if (width == 8) rex |= 0x08;  /* REX.W */
        *p++ = rex;
        *p++ = 0xF7;
        *p++ = 0xE2;                  /* mod=11, /4, r/m=010 (r10) */
    }

    return p;
}

/* ------------------------------------------------------------------ */
/*                         SIGSEGV Handler                            */
/*                       (Build Trampoline)                           */
/* ------------------------------------------------------------------ */
static void sigsegv(int sig, siginfo_t *si, void *ucv)
{
    (void)sig;
    patch_counter++;
    ucontext_t *uc = (ucontext_t *)ucv;

    /*
     * Execution lands inside bytes we already overwrote. 
     * Redirect to the matching trampoline entry.
     */
    if (redirect_if_inside_stolen_range(uc)) {
        return;
    }

    uint64_t    rip   = uc->uc_mcontext.gregs[REG_RIP];
    uint64_t    fault = (uint64_t)si->si_addr;

    int is_load  = 0;
    int is_store = 0;
    int      src_is_imm = 0;
    uint64_t imm64      = 0;

    const cs_x86_op *cmp_rhs = NULL;
    bool   is_cmp_reg_mem = false;
    const cs_x86_op *cmp_lhs = NULL;

    const cs_x86_op *add_dst  = NULL;   /* for   reg ← [mem] */

    /* -------- SIGSEGV received outside secret region -------- */
    if (fault < (uint64_t)secret || fault >= (uint64_t)secret + secret_len) {
        DBG("❌ [BUG] segv outside secret: fault=%p, secret=[%p..%p), rip=%p❌",
            (void*)fault,
            (void*)secret,
            (void*)(secret + secret_len),
            (void*)rip);

        print_instruction(rip);
        DBG("Disassembling at fault/RIP:");
        dump_code_around(rip, 10, 10);
        DBG(" regs: RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx",
            uc->uc_mcontext.gregs[REG_RAX],
            uc->uc_mcontext.gregs[REG_RBX],
            uc->uc_mcontext.gregs[REG_RCX],
            uc->uc_mcontext.gregs[REG_RDX]);
        DBG("       RSI=0x%llx RDI=0x%llx RBP=0x%llx RSP=0x%llx",
            uc->uc_mcontext.gregs[REG_RSI],
            uc->uc_mcontext.gregs[REG_RDI],
            uc->uc_mcontext.gregs[REG_RBP],
            uc->uc_mcontext.gregs[REG_RSP]);

        // Fall through to default to get a real back-trace
        signal(SIGSEGV, SIG_DFL);
        return;
    }

    DBG("🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺");
    dump("encrypted_secret", (uint8_t*)encrypted_secret, 64);
    // dump("secret_mask_page", (uint8_t*)secret_mask_page, 32);
    DBG("Patching Instruction Number=%d", patch_counter); 
    DBG("secret=%p  enc=%p  DELTA=%lld", secret, encrypted_secret, (long long)SHADOW_DELTA);
    DBG( "✅[INFO] Caught SIGSEGV! Fault address: %p (Inside secret region)✅\n", si->si_addr);
    print_instruction(rip);
    DBG( "Instruction Sequence:\n");
    dump_code(rip, 32);

    /* -------------------- already patched? -------------------- */
    patch_t *p;
    HASH_FIND(hh, patches, &rip, sizeof(rip), p);
    if (p) ABORT("patch already exists for rip=0x%llx", (unsigned long long)rip);

    /* create patch record to record stolen-entry mappings while building */
    p = (patch_t *)calloc(1, sizeof(*p));
    if (!p) ABORT("oom patch record");
    p->rip = rip;

    /* ---------- disassemble *first* instruction ---------- */
    cs_insn *ins;
    size_t width;
    if (cs_disasm(cs, (uint8_t *)rip, 15, rip, 1, &ins) != 1)
        ABORT("failed to decode instruction at 0x%llx", (unsigned long long)rip);
    /* 🚨 scratch register hazard? */
    if (dest_is_scratch_and_src_is_mem(&ins[0])) {
        DBG("⚠️⚠️  slow-path: %s %s writes to scratch (RDI/R11/R10) ⚠️⚠️",ins[0].mnemonic, ins[0].op_str);
    }
    int clobber = scratch_dest_mask(ins);

    /* ==================== DEBUG DUMP ==================== */
    // DBG("Capstone: id=%u  mnemonic=\"%s\"  size=%u",
    //     ins[0].id, ins[0].mnemonic, ins[0].size);

    // const cs_x86 *xd = &ins[0].detail->x86;
    // DBG("prefix bytes = %02x %02x %02x %02x",
    //     xd->prefix[0], xd->prefix[1], xd->prefix[2], xd->prefix[3]);

    // for (int g = 0; g < ins[0].detail->groups_count; g++)
    //     DBG(" group[%d] = %u", g, ins[0].detail->groups[g]);
    /* ===================================================== */

    int rep = rep_kind(ins);
    bool is_rep = (rep != 0);

    bool is_movs = (ins->id == X86_INS_MOVSB || ins->id == X86_INS_MOVSW ||
                    ins->id == X86_INS_MOVSD || ins->id == X86_INS_MOVSQ);
    bool is_stos = (ins->id == X86_INS_STOSB || ins->id == X86_INS_STOSW ||
                    ins->id == X86_INS_STOSD || ins->id == X86_INS_STOSQ);

    if (is_rep && !(is_movs || is_stos)) {
        ABORT("unsupported REP-prefixed instruction: %s %s",
            ins[0].mnemonic, ins[0].op_str);
    }

    if ((is_movs || is_stos) && rep == 2) {
        ABORT("unsupported REPNE (F2) on %s %s", ins[0].mnemonic, ins[0].op_str);
    }

    if (is_rep && (is_movs || is_stos)) {
        clobber |= 1;        // bit 0 = skip RDI in save/restore
    }

    const cs_x86   *x   = &ins[0].detail->x86;
    const cs_x86_op*mem = NULL;
    for (int i=0;i<x->op_count;i++)
        if (x->operands[i].type == X86_OP_MEM) { mem=&x->operands[i]; break; }

    if (!mem) ABORT("no MEM operand?");          /* unexpected: decoded instruction has no memory operand */

    uint64_t orig_addr = effective_addr(uc, mem, rip, ins[0].size);

    /* Outside the secret range */
    if (!(is_rep && (is_movs || is_stos)) && (orig_addr < (uint64_t)secret || orig_addr >= (uint64_t)secret + secret_len))
        { 
            DBG("❌ [BUG] [Effective Addr] segv outside secret: fault=%p, secret=[%p..%p), rip=%p❌",
            (void*)fault,
            (void*)secret,
            (void*)(secret + secret_len),
            (void*)rip);
            signal(SIGSEGV, SIG_DFL); return; 
        }

    const uint64_t secret_lo = (uint64_t)secret;
    const uint64_t secret_hi = secret_lo + secret_len;

    switch (ins[0].id) {
        case X86_INS_MOV:
            if (ins[0].detail->x86.operands[0].type == X86_OP_REG &&
                ins[0].detail->x86.operands[1].type == X86_OP_MEM) {
                /* mov reg , [mem]  → pure load */
                is_load = 1;
            } else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                    ins[0].detail->x86.operands[1].type == X86_OP_REG) {
                /* mov [mem] , reg  → store */
                is_store = 1;
            } else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                    ins[0].detail->x86.operands[1].type == X86_OP_IMM) {
                /* mov [mem] , immXX → store immediate */
                is_store   = 1;
                src_is_imm = 1;
                imm64      = ins[0].detail->x86.operands[1].imm;
            }
                            
            break;
        case X86_INS_MOVQ:
            /*
            * Support ONLY XMM <-> m64:
            *   movq xmm, [mem]
            *   movq [mem], xmm
            */
            if (ins[0].detail->x86.operands[0].type == X86_OP_REG &&
                ins[0].detail->x86.operands[1].type == X86_OP_MEM &&
                xmm_id(ins[0].detail->x86.operands[0].reg) >= 0) {
                is_load = 1;
            } else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                    ins[0].detail->x86.operands[1].type == X86_OP_REG &&
                    xmm_id(ins[0].detail->x86.operands[1].reg) >= 0) {
                is_store = 1;
            } else {
                goto unsupported;
            }
            break;
        case X86_INS_MOVZX:
        case X86_INS_MOVSX:
        case X86_INS_MOVSXD:
            is_load = 1;
            break;

        case X86_INS_MUL:
            if (ins[0].detail->x86.operands[0].type == X86_OP_MEM) {
                is_load = 1;   /* implicit RAX * [mem] */
            } else {
                goto unsupported;
            }
            break;

        case X86_INS_ADD:
            {
                if (ins[0].detail->x86.operands[0].type == X86_OP_REG &&
                    ins[0].detail->x86.operands[1].type == X86_OP_MEM)
                {
                    /* ADD reg, [mem] → fast-path */
                    add_dst = &ins[0].detail->x86.operands[0];
                    is_load = 1;
                }
                else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                        ins[0].detail->x86.operands[1].type == X86_OP_REG)
                {
                    /* ADD [mem], reg → RMW */
                    is_store = is_load = 1;
                }
                else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                        ins[0].detail->x86.operands[1].type == X86_OP_IMM)
                {
                    /* ADD [mem], immXX → immediate RMW */
                    is_store   = 1;
                    is_load    = 1;
                    src_is_imm = 1;
                    imm64      = ins[0].detail->x86.operands[1].imm;
                }
                else {
                    goto unsupported;
                }
            }
            break;
        case X86_INS_SBB:
            {
                if (ins[0].detail->x86.operands[0].type == X86_OP_REG &&
                    ins[0].detail->x86.operands[1].type == X86_OP_MEM)
                {
                    /* SBB reg, [mem] -> load from shadow, arithmetic uses incoming CF */
                    is_load = 1;
                }
                else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                         ins[0].detail->x86.operands[1].type == X86_OP_REG)
                {
                    /* SBB [mem], reg -> RMW */
                    is_store = is_load = 1;
                }
                else {
                    goto unsupported;
                }
            }
            break;
        case X86_INS_XOR:
            if (ins[0].detail->x86.operands[0].type == X86_OP_MEM && ins[0].detail->x86.operands[1].type == X86_OP_IMM ) {
                is_store   = 1;   /* RMW                         */
                is_load    = 1;   /* read old byte/word/dword    */
                src_is_imm = 1;   /* tell later code we have imm */
                imm64      = ins[0].detail->x86.operands[1].imm;
            }
            else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM) {
                is_store = 1;
                is_load  = 1;          /* RMW reads old value */
            } else if (ins[0].detail->x86.operands[1].type == X86_OP_MEM) {
                is_load  = 1;          /* reg ^= mem          */
            } else goto unsupported;   /* neither operand is mem */
            break;
        case X86_INS_OR:
            /* form #1: OR [mem], immXX  → RMW with immediate */
            if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                ins[0].detail->x86.operands[1].type == X86_OP_IMM) {
                is_store   = 1;   /* we will write back */
                is_load    = 1;   /* we need the old value */
                src_is_imm = 1;   /* immediate RMW */
                imm64      = ins[0].detail->x86.operands[1].imm;
            }
            /* form #2: OR [mem], reg  → plain RMW */
            else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                    ins[0].detail->x86.operands[1].type == X86_OP_REG) {
                is_store = is_load = 1;
            }
            /* form #3: OR reg, [mem]  → load only */
            else if (ins[0].detail->x86.operands[1].type == X86_OP_MEM) {
                is_load = 1;
            }
            break;
        case X86_INS_AND:
            /* form #1: AND [mem], immXX  → RMW with immediate */
            if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                ins[0].detail->x86.operands[1].type == X86_OP_IMM) {
                is_store   = 1;   /* we will write back */
                is_load    = 1;   /* we need the old value */
                src_is_imm = 1;   /* immediate RMW */
                imm64      = ins[0].detail->x86.operands[1].imm;
            }
            /* form #2: AND [mem], reg  → plain RMW */
            else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
                     ins[0].detail->x86.operands[1].type == X86_OP_REG) {
                is_store = is_load = 1;
            }
            /* form #3: AND reg, [mem]  → load only */
            else if (ins[0].detail->x86.operands[1].type == X86_OP_MEM) {
                is_load = 1;
            }
            else goto unsupported;
            break;
        /* --------------------------- vector moves ------------------------ */
        case X86_INS_MOVAPS:   /* aligned store/load, 128 bit */
        case X86_INS_MOVUPS:   /* unaligned                   */
        case X86_INS_MOVAPD:
        case X86_INS_MOVUPD:
        case X86_INS_VMOVDQA:        /* aligned  mov */
        case X86_INS_VMOVDQU:        /* UNALIGNED mov */
        case X86_INS_MOVDQA:   /* SSE2 aligned 128‑bit        */
        case X86_INS_MOVDQU:   /* SSE2 unaligned 128‑bit      */
        /* Capstone 5+ AVX-512 names: */
        case X86_INS_VMOVDQU32:
        case X86_INS_VMOVDQU64:
            /* vmovdqa ymm0,[mem]  OR  vmovdqa [mem],ymm0          */
            is_load  = (ins[0].detail->x86.operands[1].type == X86_OP_MEM);
            is_store = (ins[0].detail->x86.operands[0].type == X86_OP_MEM);
            break;
        /* ------------------- REP string-move primitives ------------------ */
        case X86_INS_MOVSB: case X86_INS_MOVSW:
        case X86_INS_MOVSD: case X86_INS_MOVSQ:
            /* these read from [RSI] and write to [RDI] */
            is_load  = 1;
            is_store = 1;
            break;

        case X86_INS_STOSB: case X86_INS_STOSW:
        case X86_INS_STOSD: case X86_INS_STOSQ:
            /* STOS* only writes to [RDI] */
            is_store = 1;
            break;
        /* ------------------- CMP------------------- */
        case X86_INS_CMP: {
            const cs_x86   *x   = &ins[0].detail->x86;
            const cs_x86_op *op0 = &x->operands[0];
            const cs_x86_op *op1 = &x->operands[1];

            if (op0->type == X86_OP_MEM &&
                (op1->type == X86_OP_REG || op1->type == X86_OP_IMM)) {
                /* form #1: cmp [mem], imm/reg */
                is_load        = 1;
                cmp_rhs        = op1;
                mem            = op0;
            }
            else if (op1->type == X86_OP_MEM && op0->type == X86_OP_REG) {
                /* form #2: cmp reg, [mem] */
                is_cmp_reg_mem = true;
                cmp_lhs        = op0;
                mem            = op1;
            }
            else {
                goto unsupported;
            }
            break;
        }
        case X86_INS_TEST: {
            const cs_x86 *x = &ins[0].detail->x86;
            const cs_x86_op *op0 = &x->operands[0], *op1 = &x->operands[1];
            if (op0->type == X86_OP_MEM && op1->type == X86_OP_IMM) {
            /* TEST [mem], imm8/32  →  read-only load + immediate */
            is_load    = 1;
            src_is_imm = 1;
            imm64      = op1->imm;
            mem        = op0;
            }
            else {
            goto unsupported;
            }
            break;
        }
    }    

    /* ---------------- common metadata ---------------- */
    const cs_x86_op *dst = &ins[0].detail->x86.operands[0];
    int sign_ext = (ins[0].id == X86_INS_MOVSX || ins[0].id == X86_INS_MOVSXD);

    if (is_store) {
        /* store or RMW: destination memory width */
        width = ins[0].detail->x86.operands[0].size;
        sign_ext = 0;
    } else {
        /* pure load / read-only memory operand */
        if (ins[0].id == X86_INS_MOV) {
            width = dst->size;
        } else if (ins[0].id == X86_INS_MUL) {
            /* MUL has a single explicit r/m operand at op0 */
            width = ins[0].detail->x86.operands[0].size;
        } else if (ins[0].detail->x86.op_count >= 2) {
            width = ins[0].detail->x86.operands[1].size;
        } else if (ins[0].detail->x86.op_count >= 1) {
            width = ins[0].detail->x86.operands[0].size;
        } else {
            ABORT("cannot determine operand width for %s %s",
                ins[0].mnemonic, ins[0].op_str);
        }
    }

    #define STEAL_INIT   2048            /* start with 256 bytes */
    #define TRAMP_GROW   64              /* worst‐case expansion factor */
    #define TRAMP_SLACK  2048
    
    size_t   steal   = 0;
    size_t   cap     = STEAL_INIT;       /* current capacity of ‘orig’ */
    uint8_t *orig    = malloc(cap);
    if (!orig) ABORT("oom");

    DBG("decide: load=%d store=%d width=%zu sign=%d", is_load, is_store, width, sign_ext); 
    goto build_trampoline;        /* skip the unsupported block */

unsupported:
    fprintf(stderr,"[!] unsupported access at 0x%llx\n",
            (unsigned long long)rip);
    abort();

build_trampoline:
    /* ------------------------------------------------------------------ */
    /*    Steal only the minimum bytes needed to place the site jump.     */
    /*    Do NOT consume later secret-touching instructions here.         */
    /*    They must remain patchable at their own original addresses.     */
    /* ------------------------------------------------------------------ */
    steal = 0;

    const size_t min_patch_bytes = 5;   /* alloc_near() keeps tramp rel32-reachable */

    while (steal < min_patch_bytes) {
        uintptr_t pc   = rip + steal;
        uintptr_t pend = (pc & ~(pagesize()-1)) + pagesize();
        size_t left = pend - pc;
        size_t max  = (left >= 15) ? 15 : left + 15;

        cs_insn *tmp = NULL;
        size_t n = cs_disasm(cs, (uint8_t *)pc, max, pc, 1, &tmp);
        if (n != 1) {
            if (left < 15) {
                max = left + 15;
                n   = cs_disasm(cs, (uint8_t *)pc, max, pc, 1, &tmp);
            }
            if (n != 1) ABORT("decode failed");
        }

        if (steal + tmp[0].size > cap) {
            cap *= 2;
            orig = realloc(orig, cap);
            if (!orig) ABORT("oom-realloc");
        }

        memcpy(orig + steal, tmp[0].bytes, tmp[0].size);
        steal += tmp[0].size;

        cs_free(tmp, 1);
    }

    DBG("steal=%zu orig=%02x %02x %02x %02x %02x", steal, orig[0],orig[1],orig[2],orig[3],orig[4]);

    /* -------------------------------------------------------------- */
    /*              build trampoline in RWX anon page                 */
    /* -------------------------------------------------------------- */
    size_t   tramp_len = steal * TRAMP_GROW + TRAMP_SLACK;
    uint8_t *tramp     = alloc_near(rip, tramp_len);
    uint8_t *t = tramp;
    size_t ins_len = ins[0].size;
    size_t ofs = 0;
    int      tail_is_terminal = 0;      /* 0 = falls back, 1 = never returns */
    /* ---- need to patch the back-jump later if steal grows ---- */
    uint8_t *back_dst_ptr = NULL;   /* points at rel32 or imm64 to fix */
    int      back_is_rel32 = 0;     /* 1 = E9 rel32, 0 = movabs+jmp   */

    int preserve_flags = preserve_incoming_flags_for_translated_insn(&ins[0]);

    /*  save caller registers just once */
    t = save_regs(t, clobber, preserve_flags);

    /* entry point corresponding to the original faulting instruction */
    patch_add_entry(p, rip, (uint64_t)t);

    /* -------------------------------------------------------------- */
    /*           Translate the faulting instruction itself            */
    /* -------------------------------------------------------------- */
    if (is_rep && (is_movs || is_stos)) {
        DBG("REP MOVS/STOS path: %s %s", ins[0].mnemonic, ins[0].op_str);

        size_t unit = (ins[0].id == X86_INS_MOVSB || ins[0].id == X86_INS_STOSB) ? 1 :
                      (ins[0].id == X86_INS_MOVSW || ins[0].id == X86_INS_STOSW) ? 2 :
                      (ins[0].id == X86_INS_MOVSD || ins[0].id == X86_INS_STOSD) ? 4 : 8;

        t = emit_rep_movs_stos(t, is_movs, unit);
        /*
         * REP helper emulates only the first instruction.
         * If we stole additional bytes for the site patch, we must re-emit
         * them starting exactly at rip + ins_len.
         */
        t = restore_regs(t, clobber, preserve_flags);

        ofs = ins_len;

        DBG("REP site: ins_len=%zu steal=%zu tail_start=%zu tail_bytes=%zu",
            ins_len, steal, ofs, steal - ofs);

        goto resume_tail_reemit;
    } else if (ins[0].id == X86_INS_MUL && is_load) {
        DBG("MUL load");

        cs_x86_op r10op = {
            .type = X86_OP_REG,
            .reg  = (width == 1) ? X86_REG_R10B :
                    (width == 2) ? X86_REG_R10W :
                    (width == 4) ? X86_REG_R10D : X86_REG_R10,
            .size = width
        };

        /* r11 = shadow address */
        t = emit_lea_r11(t, mem, rip, ins[0].size);
        t = emit_add_r11_imm(t, SHADOW_DELTA);

        /* r10 = plaintext operand */
        t = emit_load_r10_from_r11(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);

        /* execute architectural MUL using scratch operand in r10 */
        t = emit_mul_rax_r10(t, width);
    } else if (ins[0].id == X86_INS_CMP && is_load) {
        /* load mem → r11, then cmp r11, rhs */
        cs_x86_op r11op = {
            .type = X86_OP_REG,
                .reg  = X86_REG_R11,
                .size = width   /* or op0->size in the tail path */
            };
        t = emit_lea_r11(t, mem, rip, ins[0].size);        /* EA → r11       */
        t = emit_add_r11_imm(t, SHADOW_DELTA);           /* to shadow      */
        t = emit_load_from_shadow(t, &r11op, width, 0, 0);   /* [r11] → r11  */
        t = emit_xor_with_mask(t, &r11op, width,
                               (width==16)?1:(width==32)?2:0);
        t = emit_cmp_r11(t, cmp_rhs, width);
    }
    else if (ins[0].id == X86_INS_CMP && is_cmp_reg_mem) {
        /* form #2: cmp reg, [mem] */
        cs_x86_op r11op = {
            .type = X86_OP_REG,
            .reg  = X86_REG_R11,
            .size = width
        };
        t = emit_lea_r11(t, mem, rip, ins[0].size);
        t = emit_add_r11_imm(      t, SHADOW_DELTA);
        t = emit_load_from_shadow( t, &r11op, width, 0, 0);
        t = emit_xor_with_mask(    t, &r11op, width,
                                   (width==16)?1:(width==32)?2:0);

        /* now emit:   CMP  dst_reg, R11 */
        int     dst_id = rm_id(cmp_lhs);
        uint8_t rex    = 0x40 | 0x01;       /* REX.B=1 for r/m = R11 */
        if (dst_id & 8)    rex |= 0x04;     /* REX.R if dst high reg */
        if (width == 8) rex |= 0x08;        /* width is in BYTES */     /* REX.W for 64-bit compares */
        *t++ = rex;
        *t++ = 0x3B;                        /* opcode: CMP r32/64, r/m32/64 */
        /* build ModR/M: mod=11 (reg), reg=dst_id, r/m=R11.lowbits (3) */
        uint8_t modrm = (3 << 6)             /* mod=11 → register */
                        | ((dst_id & 7) << 3)/* reg = dst_id &7 */
                        | (11    & 7);       /* r/m = R11 low-3bits = 3 */
        *t++ = modrm;
    }
    else if (is_load && ins[0].id == X86_INS_XOR &&
             ins[0].detail->x86.operands[1].type == X86_OP_MEM) {
        DBG("XOR loading");

    /* ---------- xor dst_reg, [mem] ---------- */
    const cs_x86_op *dst = &ins[0].detail->x86.operands[0];

    int dst_is_scratch =
        (dst->reg == X86_REG_R11 || dst->reg == X86_REG_R11D ||
        dst->reg == X86_REG_R10 || dst->reg == X86_REG_R10D ||
        dst->reg == X86_REG_RDI || dst->reg == X86_REG_EDI);

    /* ───────────────────── slow-path only when dst is scratch ───────────────────── */
    if (dst_is_scratch) {
        t = emit_xor_reg_mem_preserve_scratch(t, dst, mem, rip, ins[0].size, width);
    }
    /* ─────────────────────────── fast-path (no scratch) ─────────────────────────── */
    else {
        // r11 = shadow address
        t = emit_lea_r11(t, mem, rip, ins[0].size);
        t = emit_add_r11_imm(t, SHADOW_DELTA);

        // load plaintext into r11
        cs_x86_op r11op = { .type = X86_OP_REG,
                            .reg  = X86_REG_R11,
                            .size = width };
        t = emit_load_from_shadow(t, &r11op, width, 0, 0);

        // unmask it in r11
        t = emit_xor_with_mask(t, &r11op, width,
                            (width==16)?1:(width==32)?2:0);

        // xor dst, r11
        uint8_t dst_id = rm_id(dst);
        uint8_t rex    = 0x40 | 0x04; // R selects r11
        if (dst_id & 8) rex |= 0x01;
        if (width == 8) rex |= 0x08;
        *t++ = rex;
        *t++ = 0x31;
        *t++ = 0xD8 | (dst_id & 7);
    }

    } else if (is_store && src_is_imm && ins[0].id == X86_INS_XOR) {
        DBG("XOR Store/RMW");

        cs_x86_op r10op = {
            .type = X86_OP_REG,
            .reg  = (width == 1) ? X86_REG_R10B :
                    (width == 2) ? X86_REG_R10W :
                    (width == 4) ? X86_REG_R10D : X86_REG_R10,
            .size = width
        };

        t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);

        /* plaintext := load(shadow) ^ old_mask */
        t = emit_load_r10_from_r11(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);

        /* plaintext ^= imm  -- FLAGS ARE DEFINED HERE */
        t = emit_group1_r10_imm(t, 6 /* XOR */, width, imm64);

        *t++ = 0x9C;   /* pushfq : preserve result flags of XOR */

        /* refresh mask for this written range */
        t = emit_refresh_mask_inline_aes(t, width);
        // t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);

        /* ciphertext := plaintext ^ new_mask */
        t = emit_xor_with_mask(t, &r10op, width, 0);
        t = emit_store_r10_to_r11(t, width);

        *t++ = 0x9D;   /* popfq : restore original XOR flags */
        } else if (is_store && src_is_imm && ins[0].id == X86_INS_OR) {
            DBG("OR Store/RMW");

            cs_x86_op r10op = {
                .type = X86_OP_REG,
                .reg  = (width == 1) ? X86_REG_R10B :
                        (width == 2) ? X86_REG_R10W :
                        (width == 4) ? X86_REG_R10D : X86_REG_R10,
                .size = width
            };

            t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);
            t = emit_load_r10_from_r11(t, width);
            t = emit_xor_with_mask(t, &r10op, width, 0);

            t = emit_group1_r10_imm(t, 1 /* OR */, width, imm64);

            *t++ = 0x9C;   /* pushfq : preserve OR result flags */

            t = emit_refresh_mask_inline_aes(t, width);
            // t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);

            t = emit_xor_with_mask(t, &r10op, width, 0);
            t = emit_store_r10_to_r11(t, width);

            *t++ = 0x9D;   /* popfq */
    } else if (is_store && src_is_imm && ins[0].id == X86_INS_AND) {
        DBG("AND Store/RMW");

        cs_x86_op r10op = {
            .type = X86_OP_REG,
            .reg  = (width == 1) ? X86_REG_R10B :
                    (width == 2) ? X86_REG_R10W :
                    (width == 4) ? X86_REG_R10D : X86_REG_R10,
            .size = width
        };

        t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);

        t = emit_load_r10_from_r11(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);

        t = emit_group1_r10_imm(t, 4 /* AND */, width, imm64);

        *t++ = 0x9C;   /* pushfq : preserve AND result flags */

        t = emit_refresh_mask_inline_aes(t, width);
        // t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);

        t = emit_xor_with_mask(t, &r10op, width, 0);
        t = emit_store_r10_to_r11(t, width);

        *t++ = 0x9D;   /* popfq */
    } else if (is_load && ins[0].id == X86_INS_OR && ins[0].detail->x86.operands[1].type == X86_OP_MEM) {
        DBG("OR Load");
        // 1) lea r11,mem ; add r11,SHADOW_DELTA
        t = emit_lea_r11(t, mem, rip, ins[0].size);
        t = emit_add_r11_imm(t, SHADOW_DELTA);
        // 2) load+unmask in r11
        cs_x86_op r11op = { .type = X86_OP_REG, .reg = X86_REG_R11, .size = width };
        t = emit_load_from_shadow(t, &r11op, width, 0, 0);
        t = emit_xor_with_mask(t, &r11op, width, 
                               (width==16)?1:(width==32)?2:0);
        // 3) OR dst_reg, r11
        int dst_id = rm_id(&ins[0].detail->x86.operands[0]);
        uint8_t rex = 0x40 | 0x04                   /* R=1 for r11 */
                    | ((dst_id & 8)?0x01:0)        /* B if dst high */
                    | ((width==8)?0x08:0);         /* W for 64b */
        *t++ = rex;
        *t++ = 0x09;  /* opcode: OR r/m,r */
        *t++ = 0xC0 | ((dst_id & 7)<<3) | 3;  /* mod=11, reg=dst, rm=r11 */
    } else if (ins[0].id == X86_INS_TEST && is_load && src_is_imm) {
        DBG("Test Immediate Load");
        /* 1) compute shadow address into R11 */
        t = emit_lea_r11(t, mem, rip, ins[0].size);
        t = emit_add_r11_imm(t, SHADOW_DELTA);

        /* 2) load + unmask into R11 */
        cs_x86_op r11op = {
          .type = X86_OP_REG,
          .reg  = X86_REG_R11,
          .size = width
        };
        t = emit_load_from_shadow(t, &r11op, width, 0, 0);
        t = emit_xor_with_mask(t, &r11op, width,
                               (width==16)?1:(width==32)?2:0);

        /* 3) now TEST R11, imm */
        t = emit_test_reg_imm(t,
                              /*reg=*/ rm_id(&r11op),
                              width,
                              imm64);
    } else if (is_load && ins[0].id == X86_INS_SBB &&
               ins[0].detail->x86.operands[0].type == X86_OP_REG &&
               ins[0].detail->x86.operands[1].type == X86_OP_MEM) {
        DBG("SBB reg, [mem]");

        const cs_x86_op *dst_op = &ins[0].detail->x86.operands[0];

        cs_x86_op r10op = {
            .type = X86_OP_REG,
            .reg  = (width == 1) ? X86_REG_R10B :
                    (width == 2) ? X86_REG_R10W :
                    (width == 4) ? X86_REG_R10D : X86_REG_R10,
            .size = width
        };

        /*
         * SBB consumes incoming CF.
         * Preserve original flags across helper code and restore them
         * immediately before the real SBB.
         */
        *t++ = 0x9C;   /* pushfq */

        /* plaintext source -> r10 */
        t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);
        t = emit_load_r10_from_r11(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);

        *t++ = 0x9D;   /* popfq : restore incoming CF for SBB */

        /* dst = dst - r10 - CF  ; flags defined here */
        {
            int dst_id = rm_id(dst_op);
            if (dst_id < 0) ABORT("SBB reg,[mem]: bad dst reg");

            if (width == 2) *t++ = 0x66;

            /* opcode: 18 /r for byte, 19 /r otherwise ; r/m = dst, reg = r10 */
            uint8_t rex = 0x40;
            if (width == 8) rex |= 0x08;      /* W */
            rex |= 0x04;                      /* R = r10 */
            if (dst_id & 8) rex |= 0x01;      /* B = dst */
            *t++ = rex;

            *t++ = (width == 1) ? 0x18 : 0x19;   /* sbb r/m, reg */
            *t++ = (uint8_t)(0xC0 | ((2 & 7) << 3) | (dst_id & 7));
        }
    } else if (is_load && is_store &&
               ins[0].id == X86_INS_SBB &&
               ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
               ins[0].detail->x86.operands[1].type == X86_OP_REG) {
        DBG("SBB [mem], reg (RMW)");

        const cs_x86_op *src_op = &ins[0].detail->x86.operands[1];

        cs_x86_op r10op = {
            .type = X86_OP_REG,
            .reg  = (width == 1) ? X86_REG_R10B :
                    (width == 2) ? X86_REG_R10W :
                    (width == 4) ? X86_REG_R10D : X86_REG_R10,
            .size = width
        };

        /*
         * First preserve incoming CF across helper code so the real SBB
         * sees the correct borrow input.
         */
        *t++ = 0x9C;   /* pushfq */

        t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);

        /* plaintext := load(shadow) ^ old_mask */
        t = emit_load_r10_from_r11(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);

        *t++ = 0x9D;   /* popfq : restore incoming CF for SBB */

        /* plaintext = plaintext - src - CF ; flags defined here */
        t = emit_sbb_r10_reg(t, src_op, width);

        /*
         * Now preserve the RESULT flags of SBB across the post-SBB helper code.
         */
        *t++ = 0x9C;   /* pushfq */

        t = emit_refresh_mask_inline_aes(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);
        t = emit_store_r10_to_r11(t, width);

        *t++ = 0x9D;   /* popfq */
    } else if (is_load && ins[0].id == X86_INS_ADD && add_dst) {
        DBG("Add Dest");
        /* --- ADD dst_reg, [mem]: load & unmask into R11, then ADD dst,R11 --- */
        cs_x86_op r11op = {
            .type = X86_OP_REG,
            .reg  = X86_REG_R11,
            .size = width
        };
        /* 1) compute shadow address into R11 */
        t = emit_lea_r11(t, mem, rip, ins[0].size);
        t = emit_add_r11_imm(t, SHADOW_DELTA);

        /* 2) load plaintext from shadow, xor-unmask in R11 */
        t = emit_load_from_shadow(t, &r11op, width, 0, 0);
        t = emit_xor_with_mask   (t, &r11op, width,
                     (width==16)?1 : (width==32)?2 : 0);

        int r11_id = rm_id(&r11op);
        /* 3) emit: ADD dst_reg, R11 */
        {
            /* which GPR is the destination? */
            const cs_x86_op *dst = add_dst;
            int dst_id = rm_id(dst);

            /* REX prefix */
            uint8_t rex = 0x40;
            if (width == 8) rex |= 0x08;          /* W=1 for 64-bit */
            if ( r11_id    & 8) rex |= 0x04;      /* R=1 if R11 is one of R8–R15 */
            if ((dst_id  & 8) != 0) rex |= 0x01;  /* B=1 if dst high */
            *t++ = rex;

            /* opcode 01 /r = ADD r/m64, r64 */
            *t++ = 0x01;

            /* mod=11, reg=low3(r11), rm=low3(dst) */
            uint8_t modrm = 0xC0
                        | ((r11_id    & 7) << 3)
                        | ( dst_id    & 7);
            *t++ = modrm;
        }
    } else if (is_store && src_is_imm && ins[0].id == X86_INS_ADD) {
        DBG("ADD Store/RMW immediate");

        cs_x86_op r10op = {
            .type = X86_OP_REG,
            .reg  = (width == 1) ? X86_REG_R10B :
                    (width == 2) ? X86_REG_R10W :
                    (width == 4) ? X86_REG_R10D : X86_REG_R10,
            .size = width
        };

        t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);

        /* plaintext := load(shadow) ^ old_mask */
        t = emit_load_r10_from_r11(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);

        /* plaintext += imm  -- FLAGS ARE DEFINED HERE */
        t = emit_group1_r10_imm(t, 0 /* ADD */, width, imm64);

        *t++ = 0x9C;   /* pushfq : preserve ADD result flags */

        /* refresh mask + re-mask + store */
        t = emit_refresh_mask_inline_aes(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);
        t = emit_store_r10_to_r11(t, width);

        *t++ = 0x9D;   /* popfq */
    } else if (is_load && is_store &&
        ins[0].id == X86_INS_ADD &&
        ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
        ins[0].detail->x86.operands[1].type == X86_OP_REG) {
        DBG("RMW ADD([mem], reg)");

        const cs_x86_op *mop = &ins[0].detail->x86.operands[0];
        const cs_x86_op *rop = &ins[0].detail->x86.operands[1];

        cs_x86_op r10op = {
            .type = X86_OP_REG,
            .reg  = (width == 1) ? X86_REG_R10B :
                    (width == 2) ? X86_REG_R10W :
                    (width == 4) ? X86_REG_R10D : X86_REG_R10,
            .size = width
        };

        t = emit_recompute_shadow_r11(t, mop, rip, ins[0].size);

        /* plaintext := load(shadow) ^ old_mask */
        t = emit_load_r10_from_r11(t, width);
        t = emit_xor_with_mask(t, &r10op, width, 0);

        /* plaintext += src_reg -- FLAGS ARE DEFINED HERE */
        t = emit_binop_r10_reg(t, 0x00 /* ADD */, rop, width);

        *t++ = 0x9C;   /* pushfq : preserve ADD result flags */

        /* refresh mask + re-mask + store */
        t = emit_refresh_mask_inline_aes(t, width);
        // t = emit_recompute_shadow_r11(t, mop, rip, ins[0].size);
        t = emit_xor_with_mask(t, &r10op, width, 0);
        t = emit_store_r10_to_r11(t, width);

        *t++ = 0x9D;   /* popfq */
    } else if (ins[0].id == X86_INS_MOVQ &&
            ins[0].detail->x86.operands[0].type == X86_OP_REG &&
            ins[0].detail->x86.operands[1].type == X86_OP_MEM &&
            xmm_id(ins[0].detail->x86.operands[0].reg) >= 0) {
        DBG("MOVQ xmm, [mem]");

        const cs_x86_op *dst_op = &ins[0].detail->x86.operands[0];

        cs_x86_op r10op = {
            .type = X86_OP_REG,
            .reg  = X86_REG_R10,
            .size = 8
        };

        /* r11 = shadow address */
        t = emit_lea_r11(t, mem, rip, ins[0].size);
        t = emit_add_r11_imm(t, SHADOW_DELTA);

        /* r10 = plaintext qword */
        t = emit_load_r10_from_r11(t, 8);
        t = emit_xor_with_mask(t, &r10op, 8, 0);

        /* xmmdst = r10 (movq semantics: low 64 bits loaded, upper cleared) */
        t = emit_movq_xmm_from_r10(t, dst_op);
    } else if (is_load) {
        DBG("Load Instruction");
        const cs_x86_op *dst_op = &ins[0].detail->x86.operands[0];

        if ((ins[0].id == X86_INS_MOV ||
            ins[0].id == X86_INS_MOVZX ||
            ins[0].id == X86_INS_MOVSX ||
            ins[0].id == X86_INS_MOVSXD) &&
            dest_is_scratch_and_src_is_mem(&ins[0])) {

            DBG("Load Instruction -> scratch-safe MOV slow path");
            t = emit_mov_reg_mem_preserve_scratch(t, dst_op, mem, rip, ins[0].size,
                                                width, sign_ext);
        } else {
            t = emit_lea_r11(t, mem, rip, ins[0].size);
            t = emit_add_r11_imm(t, SHADOW_DELTA);
            t = emit_load_from_shadow(t, dst_op, width, 0, sign_ext);
            t = emit_xor_with_mask(t, dst_op, width, (width==16)?1:(width==32)?2:0);
        }
    } else if (is_store) {
        /*Immediate Store => e.g., mov qword ptr [r12], 0 */
        if (src_is_imm) {
                DBG("Immediate Store");
                /* --- compute shadow address, refresh mask, then recompute shadow --- */
                t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);
                t   = emit_refresh_mask_inline_aes(t, width);
                // t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);
                *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;        /* mov  rdi,r11    */

                 /* --------- R10 = immediate constant --------- */
                *t++ = 0x49; *t++ = 0xBA;                     /* movabs r10,imm64*/
                memcpy(t, &imm64, 8);  t += 8;
                /* mask it if the address is inside the secret page */
                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = (width == 1) ? X86_REG_R10B :
                            (width == 2) ? X86_REG_R10W :
                            (width == 4) ? X86_REG_R10D : X86_REG_R10,
                    .size = width
                };
                t = emit_xor_with_mask(t, &r10op, width, 0);
            

                /* --------- store [rdi] ← r11  (width‑specific) --------- */
                if (width == 8) {
                    *t++ = 0x4C; *t++ = 0x89; *t++ = 0x17;    /* mov [rdi],r10   */
                } else if (width == 4) {
                    *t++ = 0x44; *t++ = 0x89; *t++ = 0x17;    /* mov [rdi],r10d  */
                } else if (width == 2) {
                    *t++ = 0x66; *t++ = 0x44; *t++ = 0x89; *t++ = 0x17;
                } else if (width == 1) {
                    *t++ = 0x44; *t++ = 0x88; *t++ = 0x17;    /* mov byte [rdi],r10b */
                } else {
                    ABORT("imm‑store: bad width %zu", width);
                }
        } else {
            DBG("Not immediate Store");
            /* src is operand 1 (a GPR) */
            const cs_x86_op *src_op = &ins[0].detail->x86.operands[1];
            if (ins[0].id == X86_INS_MOVQ &&
                src_op->type == X86_OP_REG &&
                xmm_id(src_op->reg) >= 0) {
                DBG("MOVQ [mem], xmm");

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = X86_REG_R10,
                    .size = 8
                };

                t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);
                t = emit_refresh_mask_inline_aes(t, 8);

                /* r10 = low 64 bits of xmm src */
                t = emit_movq_r10_from_xmm(t, src_op);

                /* re-mask plaintext and store ciphertext */
                t = emit_xor_with_mask(t, &r10op, 8, 0);
                t = emit_store_r10_to_r11(t, 8);

            } else {            
                /* ------------------- HAZARD: src register aliases our scratch set ------------------- */
                int src_is_scratch =
                        (src_op->reg == X86_REG_R11 || src_op->reg == X86_REG_R11D ||
                        src_op->reg == X86_REG_R10 || src_op->reg == X86_REG_R10D ||
                        src_op->reg == X86_REG_RDI || src_op->reg == X86_REG_EDI);

                if (src_is_scratch) {
                        /* Save caller’s RAX first, then the plaintext value. */
                        *t++ = 0x50;                                 /* push rax            */

                        if (src_op->reg == X86_REG_R11 || src_op->reg == X86_REG_R11D)
                                { *t++ = 0x41; *t++ = 0x53; }        /* push r11            */
                        else if (src_op->reg == X86_REG_R10 || src_op->reg == X86_REG_R10D)
                                { *t++ = 0x41; *t++ = 0x52; }        /* push r10            */
                        else                                         /* rdi / edi           */
                                { *t++ = 0x57; }                     /* push rdi            */
                }


                t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);
                t = emit_refresh_mask_inline_aes(t, width);
                // t = emit_recompute_shadow_r11(t, mem, rip, ins[0].size);
                if (src_is_scratch) {
                        *t++ = 0x58;                                 /* pop rax */
                        *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;       /* mov rdi, r11 */

                        t = emit_mask_and_store_rax_to_rdi(t, width);

                        *t++ = 0x58;                                 /* pop rax */
                } else {
                        if (width == 16 || width == 32) {
                            t = emit_store_vector_preserve_src(t, src_op, width, 0);
                        } else {
                            t = emit_mov_r10_from_reg(t, src_op, width);

                            cs_x86_op r10op = {
                                .type = X86_OP_REG,
                                .reg  = (width == 1) ? X86_REG_R10B :
                                        (width == 2) ? X86_REG_R10W :
                                        (width == 4) ? X86_REG_R10D : X86_REG_R10,
                                .size = width
                            };

                            t = emit_xor_with_mask(t, &r10op, width, 0);
                            t = emit_store_r10_to_r11(t, width);
                        }
                }
            }
        }
    } else {
        /* RMW-add etc. — adjust if we support other cases */
        ABORT("unhandled first-insn opcode %x", ins[0].id);
    }

    /* -------------------------------------------------------------- */
    /*           re-emit each extra stolen instruction safely         */
    /* -------------------------------------------------------------- */
    t = restore_regs(t, clobber, preserve_flags);
    ofs = ins_len;

resume_tail_reemit:
    while (ofs < steal) {
        cs_insn *tmp;
        size_t n = cs_disasm(cs,
                            orig + ofs,        /* bytes to decode         */
                            steal - ofs,
                            rip   + ofs,       /* correct runtime address */
                            1, &tmp);
        if (n != 1) ABORT("tail decode failed");

        /* map this original stolen instruction start to its trampoline entry */
        patch_add_entry(p, tmp[0].address, (uint64_t)t);

        // if (dest_is_scratch_and_src_is_mem(&tmp[0])) {
        //     DBG("⚠️⚠️  slow‑path: %s %s writes to scratch (RDI/R11/R10)⚠️⚠️"PRIx64, tmp[0].mnemonic, tmp[0].op_str);
        // }
        // int clobber = scratch_dest_mask(tmp);
        const cs_x86   *tx  = &tmp[0].detail->x86;
        const cs_x86_op *op0 = (tx->op_count > 0 ? &tx->operands[0] : NULL);
        const cs_x86_op*op1 = (tx->op_count > 1 ? &tx->operands[1] : NULL);

        if      (op0 && op0->type == X86_OP_MEM)  width = op0->size;
        else if (op1 && op1->type == X86_OP_MEM)  width = op1->size;

        /* --- Decide whether this instruction truly touches the secret page --- */
        int touches_secret = 0;
        uint64_t ea = 0;

        /*
         * After REP MOVS/STOS, the original signal-time ucontext is stale for
         * RCX/RSI/RDI. So a stolen tail instruction that uses RSI/RDI in a mem
         * operand cannot be classified safely from `uc`.
         */
        if (is_rep && (is_movs || is_stos)) {
            for (int i = 0; i < tx->op_count; i++) {
                const cs_x86_op *op = &tx->operands[i];
                if (op->type != X86_OP_MEM) continue;

                if (op->mem.base  == X86_REG_RSI || op->mem.base  == X86_REG_RDI ||
                    op->mem.index == X86_REG_RSI || op->mem.index == X86_REG_RDI) {
                    ABORT("REP tail uses RSI/RDI-based mem operand with stale fault-time context: %s %s",
                          tmp[0].mnemonic, tmp[0].op_str);
                }
            }
        }

        for (int i = 0; i < tx->op_count; i++) {
            const cs_x86_op *op = &tx->operands[i];
            if (op->type != X86_OP_MEM) continue;
            if (!insn_operand_reads_memory(tmp, i) && !insn_is_store(tmp))
                continue;

            ea = effective_addr(uc, op, tmp[0].address, tmp[0].size);
            if (ea >= secret_lo && ea < secret_hi) {
                touches_secret = 1;
                break;
            }
        }

        if (!touches_secret) {
            /* -------- Instruction is a direct branch we must fix -------- */
            if (is_direct_branch(tmp)) {
                uint64_t target = tmp[0].detail->x86.operands[0].imm;

                int in_slice = (target >= rip && target < rip + steal);

                if (in_slice) {
                    DBG("Target Is Inside");
                    int64_t rel = (int64_t)target - ((int64_t)(t + tmp[0].size));
                    if (rel >= INT32_MIN && rel <= INT32_MAX) {
                        if (tmp[0].id == X86_INS_JMP) {
                            *t++ = 0xE9;
                            int32_t r32 = (int32_t)rel;
                            memcpy(t, &r32, 4);  t += 4;
                        }
                        else if (tmp[0].id == X86_INS_CALL) {
                            *t++ = 0xE8;
                            int32_t r32 = (int32_t)rel;
                            memcpy(t, &r32, 4);  t += 4;
                        }
                        else if (tmp[0].id == X86_INS_LOOP ||
                                tmp[0].id == X86_INS_LOOPNE ||
                                tmp[0].id == X86_INS_LOOPE) {

                            *t++ = 0x48; *t++ = 0xFF; *t++ = 0xC9;

                            *t++ = 0x9C;
                            *t++ = 0x41; *t++ = 0x58;
                            *t++ = 0x41; *t++ = 0xF6; *t++ = 0xC0; *t++ = 0x40;

                            *t++ = 0xE3; *t++ = 0x05;

                            if (tmp[0].id == X86_INS_LOOPE || tmp[0].id == X86_INS_LOOPNE) {
                                uint8_t opcode = (tmp[0].id == X86_INS_LOOPE) ? 0x84 : 0x85;
                                *t++ = 0x0F; *t++ = opcode;
                                int32_t rel32 = (int32_t)((int64_t)target - ((int64_t)(t + 4)));
                                memcpy(t, &rel32, 4);  t += 4;
                            } else {
                                *t++ = 0xE9;
                                int32_t rel32 = (int32_t)((int64_t)target - ((int64_t)(t + 4)));
                                memcpy(t, &rel32, 4);  t += 4;
                            }
                        }
                        else {
                            uint8_t cc = tmp[0].bytes[0] & 0x0F;
                            *t++ = 0x0F; *t++ = 0x80 | cc;
                            int32_t r32 = (int32_t)rel;
                            memcpy(t, &r32, 4);  t += 4;
                        }
                    } else {
                        ABORT("rel32 out of range inside slice");
                    }
                } else {
                    DBG("Target Is Outside");

                    int64_t rel = (int64_t)target - ((int64_t)(t + 6));
                    int fits_rel32 = (rel >= INT32_MIN && rel <= INT32_MAX);

                    if (tmp[0].id == X86_INS_CALL) {
                        *t++ = 0x49; *t++ = 0xBB;
                        memcpy(t, &target, 8);  t += 8;
                        *t++ = 0x41; *t++ = 0xFF; *t++ = 0xD3;
                    }
                    else if (tmp[0].id == X86_INS_JMP) {
                        uint8_t *disp_site;
                        *t++ = 0xFF; *t++ = 0x25;
                        disp_site = t;  t += 4;
                        memcpy(t, &target, 8);  t += 8;
                        int32_t disp32 = 0;
                        memcpy(disp_site, &disp32, 4);
                    }
                    else if (tmp[0].id == X86_INS_JA   || tmp[0].id == X86_INS_JAE ||
                            tmp[0].id == X86_INS_JB   || tmp[0].id == X86_INS_JBE ||
                            tmp[0].id == X86_INS_JE   || tmp[0].id == X86_INS_JNE ||
                            tmp[0].id == X86_INS_JG   || tmp[0].id == X86_INS_JGE ||
                            tmp[0].id == X86_INS_JL   || tmp[0].id == X86_INS_JLE ||
                            tmp[0].id == X86_INS_JO   || tmp[0].id == X86_INS_JNO ||
                            tmp[0].id == X86_INS_JP   || tmp[0].id == X86_INS_JNP ||
                            tmp[0].id == X86_INS_JS   || tmp[0].id == X86_INS_JNS) {
                        DBG("conditional jcc");
                        uint8_t cc;
                        if (tmp[0].bytes[0] == 0x0F) cc = tmp[0].bytes[1] & 0x0F;
                        else                         cc = tmp[0].bytes[0] & 0x0F;

                        if (fits_rel32) {
                            *t++ = 0x0F; *t++ = 0x80 | cc;
                            int32_t r32 = (int32_t)rel;
                            memcpy(t, &r32, 4);  t += 4;
                        } else {
                            uint8_t inv = cc ^ 1;
                            *t++ = 0x70 | inv; *t++ = 0x0E;
                            *t++ = 0xFF; *t++ = 0x25;
                            uint8_t *disp_site = t;  t += 4;
                            memcpy(t, &target, 8);  t += 8;
                            int32_t zero = 0;
                            memcpy(disp_site, &zero, 4);
                        }
                    }
                    else if (tmp[0].id == X86_INS_LOOP ||
                            tmp[0].id == X86_INS_LOOPE ||
                            tmp[0].id == X86_INS_LOOPNE) {
                        *t++ = 0x48; *t++ = 0xFF; *t++ = 0xC9;
                        *t++ = 0xE3; *t++ = 0x0F;

                        if (tmp[0].id != X86_INS_LOOP) {
                            *t++ = 0x9C;
                            *t++ = 0x41; *t++ = 0x58;
                            *t++ = 0x41; *t++ = 0xF6; *t++ = 0xC0; *t++ = 0x40;
                            uint8_t cond = (tmp[0].id == X86_INS_LOOPE) ? 0x75 : 0x74;
                            *t++ = cond; *t++ = 0x07;
                        }

                        *t++ = 0xFF; *t++ = 0x25;
                        uint8_t *disp_site = t;  t += 4;
                        memcpy(t, &target, 8);  t += 8;
                        int32_t zero = 0;
                        memcpy(disp_site, &zero, 4);
                    }
                    else if (tmp[0].id == X86_INS_JRCXZ || tmp[0].id == X86_INS_JCXZ) {
                        *t++ = 0xE3; *t++ = 0x0E;
                        *t++ = 0xFF; *t++ = 0x25;
                        uint8_t *disp_site = t;  t += 4;
                        memcpy(t, &target, 8);  t += 8;
                        int32_t zero = 0;
                        memcpy(disp_site, &zero, 4);
                    }
                    else {
                        ABORT("unhandled direct branch with external target");
                    }
                }

                cs_free(tmp, 1);
                break;
            }
            else if (tmp[0].id == X86_INS_LEAVE ||
                    tmp[0].id == X86_INS_RET   ||
                    tmp[0].id == X86_INS_RETF  ||
                    (tmp[0].id == X86_INS_JMP  && tmp[0].detail->x86.operands[0].type != X86_OP_IMM) ||
                    (tmp[0].id == X86_INS_CALL && tmp[0].detail->x86.operands[0].type != X86_OP_IMM))
            {
                DBG("Target Is indirect");

                memcpy(t, tmp[0].bytes, tmp[0].size);
                t += tmp[0].size;

                if (ofs + tmp[0].size < steal &&
                    orig[ofs + tmp[0].size] == 0xC3) {
                    *t++ = 0xC3;
                    ofs += 1;
                }

                tail_is_terminal = 1;

                cs_free(tmp,1);
                break;
            }
            else if (insn_has_rip_relative_mem(tmp, NULL)) {
                DBG("relocate RIP-relative non-secret instruction");
                t = emit_relocated_rip_relative_insn(t, tmp);
            }
            else {
                DBG("copy verbatim");
                memcpy(t, tmp[0].bytes, tmp[0].size);
                t += tmp[0].size;
            }
        } 
        else {
            /* Stolen Instruction Touches Secret "Ladder" */
            const cs_x86_op *mop = (op0 && op0->type == X86_OP_MEM) ? op0 : (op1 && op1->type == X86_OP_MEM) ? op1 : NULL;
            if (!mop)  ABORT("logic bug: expected mem operand");
            // touches secret → doing the shadow load/store
            if (dest_is_scratch_and_src_is_mem(&tmp[0])) {
                DBG("⚠️⚠️  slow-path: %s %s writes to scratch (RDI/R11/R10) ⚠️⚠️", tmp[0].mnemonic, tmp[0].op_str);
            }
            int clobber = scratch_dest_mask(tmp);
            int tail_preserve_flags = preserve_incoming_flags_for_translated_insn(tmp);
            t = save_regs(t, clobber, tail_preserve_flags);
            if (tmp[0].id == X86_INS_MUL &&
                op0 && op0->type == X86_OP_MEM) {
                DBG("MUL [mem] touching secret");

                size_t w = op0->size;

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = (w == 1) ? X86_REG_R10B :
                            (w == 2) ? X86_REG_R10W :
                            (w == 4) ? X86_REG_R10D : X86_REG_R10,
                    .size = w
                };

                t = emit_recompute_shadow_r11(t, op0, tmp[0].address, tmp[0].size);
                t = emit_load_r10_from_r11(t, w);
                t = emit_xor_with_mask(t, &r10op, w, 0);
                t = emit_mul_rax_r10(t, w);
            }
            else if (tmp[0].id == X86_INS_ADD &&
                    op0->type == X86_OP_MEM &&
                    op1 && op1->type == X86_OP_IMM) {
                DBG("ADD [mem], imm touching secret (RMW)");

                size_t w = op0->size;
                uint64_t add_imm = (uint64_t)op1->imm;

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = (w == 1) ? X86_REG_R10B :
                            (w == 2) ? X86_REG_R10W :
                            (w == 4) ? X86_REG_R10D : X86_REG_R10,
                    .size = w
                };

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);

                /* plaintext := load(shadow) ^ old_mask */
                t = emit_load_r10_from_r11(t, w);
                t = emit_xor_with_mask(t, &r10op, w, 0);

                /* plaintext += imm -- FLAGS ARE DEFINED HERE */
                t = emit_group1_r10_imm(t, 0 /* ADD */, w, add_imm);

                *t++ = 0x9C;   /* pushfq */

                /* refresh mask + re-mask + store */
                t = emit_refresh_mask_inline_aes(t, w);
                t = emit_xor_with_mask(t, &r10op, w, 0);
                t = emit_store_r10_to_r11(t, w);

                *t++ = 0x9D;   /* popfq */
            }
            else if (tmp[0].id == X86_INS_ADD &&
                    op0->type == X86_OP_MEM &&
                    op1 && op1->type == X86_OP_REG) {
                size_t w = op0->size;

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = (w == 1) ? X86_REG_R10B :
                            (w == 2) ? X86_REG_R10W :
                            (w == 4) ? X86_REG_R10D : X86_REG_R10,
                    .size = w
                };

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);

                /* plaintext := load(shadow) ^ old_mask */
                t = emit_load_r10_from_r11(t, w);
                t = emit_xor_with_mask(t, &r10op, w, 0);

                /* plaintext += src_reg -- FLAGS ARE DEFINED HERE */
                t = emit_binop_r10_reg(t, 0x00 /* ADD */, op1, w);

                *t++ = 0x9C;   /* pushfq */

                /* refresh mask + re-mask + store */
                t = emit_refresh_mask_inline_aes(t, w);
                // t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_xor_with_mask(t, &r10op, w, 0);
                t = emit_store_r10_to_r11(t, w);

                *t++ = 0x9D;   /* popfq */
            } else if (tmp[0].id == X86_INS_SBB &&
                     op0->type == X86_OP_REG &&
                     op1 && op1->type == X86_OP_MEM) {
                DBG("SBB reg, [mem] touching secret");

                size_t w = op1->size;

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = (w == 1) ? X86_REG_R10B :
                            (w == 2) ? X86_REG_R10W :
                            (w == 4) ? X86_REG_R10D : X86_REG_R10,
                    .size = w
                };

                *t++ = 0x9C;   /* pushfq : preserve incoming CF */

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_load_r10_from_r11(t, w);
                t = emit_xor_with_mask(t, &r10op, w, 0);

                *t++ = 0x9D;   /* popfq : restore incoming CF */

                {
                    int dst_id = rm_id(op0);
                    if (dst_id < 0) ABORT("tail SBB reg,[mem]: bad dst reg");

                    if (w == 2) *t++ = 0x66;

                    uint8_t rex = 0x40;
                    if (w == 8) rex |= 0x08;
                    rex |= 0x04;                    /* reg = r10 */
                    if (dst_id & 8) rex |= 0x01;    /* r/m = dst */
                    *t++ = rex;

                    *t++ = (w == 1) ? 0x18 : 0x19;  /* sbb r/m, reg */
                    *t++ = (uint8_t)(0xC0 | ((2 & 7) << 3) | (dst_id & 7));
                }
            } else if (tmp[0].id == X86_INS_SBB &&
                     op0->type == X86_OP_MEM &&
                     op1 && op1->type == X86_OP_REG) {
                DBG("SBB [mem], reg touching secret (RMW)");

                size_t w = op0->size;

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = (w == 1) ? X86_REG_R10B :
                            (w == 2) ? X86_REG_R10W :
                            (w == 4) ? X86_REG_R10D : X86_REG_R10,
                    .size = w
                };

                *t++ = 0x9C;   /* pushfq : preserve incoming CF */

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);

                /* plaintext := load(shadow) ^ old_mask */
                t = emit_load_r10_from_r11(t, w);
                t = emit_xor_with_mask(t, &r10op, w, 0);

                *t++ = 0x9D;   /* popfq : restore incoming CF */

                /* plaintext = plaintext - src - CF ; flags defined here */
                t = emit_sbb_r10_reg(t, op1, w);

                *t++ = 0x9C;   /* preserve SBB result flags across helper code */

                t = emit_refresh_mask_inline_aes(t, w);
                t = emit_xor_with_mask(t, &r10op, w, 0);
                t = emit_store_r10_to_r11(t, w);

                *t++ = 0x9D;
            } else if (tmp[0].id == X86_INS_MOV &&
                    op0->type == X86_OP_MEM &&
                    op1 && op1->type == X86_OP_REG) {
                DBG("store register");

                int src_is_scratch =
                    (op1->reg == X86_REG_R11 || op1->reg == X86_REG_R11D ||
                    op1->reg == X86_REG_R10 || op1->reg == X86_REG_R10D ||
                    op1->reg == X86_REG_RDI || op1->reg == X86_REG_EDI);

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_refresh_mask_inline_aes(t, op0->size);
                // t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);

                if (src_is_scratch) {
                    *t++ = 0x50;  /* push rax */

                    if (op1->reg == X86_REG_R11 || op1->reg == X86_REG_R11D) {
                        *t++ = 0x41; *t++ = 0x53;   /* push r11 */
                    } else if (op1->reg == X86_REG_R10 || op1->reg == X86_REG_R10D) {
                        *t++ = 0x41; *t++ = 0x52;   /* push r10 */
                    } else {
                        *t++ = 0x57;                /* push rdi */
                    }

                    *t++ = 0x58;                                 /* pop rax: plaintext source */
                    *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;       /* mov rdi, r11 */

                    t = emit_mask_and_store_rax_to_rdi(t, op0->size);

                    *t++ = 0x58;                                 /* pop rax: restore caller rax */
                } else {
                    if (op0->size == 16 || op0->size == 32) {
                        t = emit_store_vector_preserve_src(t, op1, op0->size, 0);
                    } else {
                        t = emit_mov_r10_from_reg(t, op1, op0->size);

                        cs_x86_op r10op = {
                            .type = X86_OP_REG,
                            .reg  = (op0->size == 1) ? X86_REG_R10B :
                                    (op0->size == 2) ? X86_REG_R10W :
                                    (op0->size == 4) ? X86_REG_R10D : X86_REG_R10,
                            .size = op0->size
                        };

                        t = emit_xor_with_mask(t, &r10op, op0->size, 0);
                        t = emit_store_r10_to_r11(t, op0->size);
                    }
                }
            }
            else if (tmp[0].id == X86_INS_MOVQ &&
                    op0->type == X86_OP_MEM &&
                    op1 && op1->type == X86_OP_REG &&
                    xmm_id(op1->reg) >= 0) {
                DBG("MOVQ [mem], xmm touching secret");

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = X86_REG_R10,
                    .size = 8
                };

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_refresh_mask_inline_aes(t, 8);

                /* r10 = plaintext low 64 bits from xmm */
                t = emit_movq_r10_from_xmm(t, op1);

                /* ciphertext = plaintext ^ new_mask */
                t = emit_xor_with_mask(t, &r10op, 8, 0);
                t = emit_store_r10_to_r11(t, 8);
            }
            else if (tmp[0].id == X86_INS_MOV &&
                    op0->type == X86_OP_REG &&
                    op1 && op1->type == X86_OP_MEM) {
                if (dest_is_scratch_and_src_is_mem(tmp)) {
                    DBG("tail MOV reg,[mem] -> scratch-safe slow path");
                    t = emit_mov_reg_mem_preserve_scratch(t, op0, mop,
                                                        tmp[0].address, tmp[0].size,
                                                        op1->size, 0);
                } else {
                    t = emit_lea_r11(t, mop, tmp[0].address, tmp[0].size);
                    t = emit_add_r11_imm(t, SHADOW_DELTA);
                    t = emit_load_from_shadow(t, op0, op1->size, 0, 0);
                    t = emit_xor_with_mask(t, op0, width, (width==16)?1:(width==32)?2:0);
                }
            }
            else if (tmp[0].id == X86_INS_MOVQ &&
                    op0->type == X86_OP_REG &&
                    op1 && op1->type == X86_OP_MEM &&
                    xmm_id(op0->reg) >= 0) {
                DBG("MOVQ xmm, [mem] touching secret");

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = X86_REG_R10,
                    .size = 8
                };

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_load_r10_from_r11(t, 8);
                t = emit_xor_with_mask(t, &r10op, 8, 0);
                t = emit_movq_xmm_from_r10(t, op0);
            }
            else if ((tmp[0].id == X86_INS_VMOVDQA ||
                    tmp[0].id == X86_INS_VMOVDQU) &&
                    op0->type == X86_OP_MEM &&
                    op1 && op1->type == X86_OP_REG) {
                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_refresh_mask_inline_aes(t, op0->size);
                // t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_store_vector_preserve_src(t, op1, op0->size, 0);
            }
            else if ((tmp[0].id == X86_INS_VMOVDQA ||
                      tmp[0].id == X86_INS_VMOVDQU) &&
                     op0->type == X86_OP_REG &&
                     op1 && op1->type == X86_OP_MEM) {
                t = emit_lea_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_load_from_shadow(t, op0, op1->size, 0, 0);
                t = emit_xor_with_mask(t, op0, width, (width==16)?1:(width==32)?2:0);
            }
            else if ((tmp[0].id == X86_INS_MOVAPS  || tmp[0].id == X86_INS_MOVUPS ||
                    tmp[0].id == X86_INS_MOVAPD  || tmp[0].id == X86_INS_MOVUPD ||
                    tmp[0].id == X86_INS_MOVDQA  || tmp[0].id == X86_INS_MOVDQU) &&
                    op0->type == X86_OP_MEM &&
                    op1 && op1->type == X86_OP_REG) {
                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_refresh_mask_inline_aes(t, op0->size);
                // t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_store_vector_preserve_src(t, op1, op0->size, 0);
            }
            else if ((tmp[0].id == X86_INS_MOVAPS  || tmp[0].id == X86_INS_MOVUPS ||
                     tmp[0].id == X86_INS_MOVAPD  || tmp[0].id == X86_INS_MOVUPD ||
                     tmp[0].id == X86_INS_MOVDQA  || tmp[0].id == X86_INS_MOVDQU) &&
                     op0->type == X86_OP_REG &&
                     op1 && op1->type == X86_OP_MEM) {
                t = emit_lea_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_load_from_shadow(t, op0, op1->size, 0, 0);
                t = emit_xor_with_mask(t, op0, width, (width==16)?1:(width==32)?2:0);
            }
            /* -------- mov [mem], immXX  (store immediate) -------- */
            else if (tmp[0].id == X86_INS_MOV &&
                    op0->type == X86_OP_MEM &&
                    op1 && op1->type == X86_OP_IMM) {
                DBG("store immediate touching secret");

                uint64_t imm64 = (uint64_t)op1->imm;
                size_t   w     = op0->size;

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = (w == 1) ? X86_REG_R10B :
                            (w == 2) ? X86_REG_R10W :
                            (w == 4) ? X86_REG_R10D : X86_REG_R10,
                    .size = w
                };

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_refresh_mask_inline_aes(t, w);
                // t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);

                /* r10 := immediate plaintext */
                *t++ = 0x49; *t++ = 0xBA;   /* movabs r10, imm64 */
                memcpy(t, &imm64, 8); t += 8;

                /* re-mask with fresh mask, then store */
                t = emit_xor_with_mask(t, &r10op, w, 0);
                t = emit_store_r10_to_r11(t, w);
            }
            /* ---------------- cmp mem, imm/reg ---------------- */
            else if (tmp[0].id == X86_INS_CMP &&
                     op0->type == X86_OP_MEM) {
                /* load → r11 */
                cs_x86_op r11op = { .type = X86_OP_REG, .reg = X86_REG_R11, .size = op0->size };
                t = emit_lea_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_load_from_shadow(t, &r11op, op0->size,
                                         0, 0);
                t = emit_xor_with_mask(t, &r11op, width, (width==16)?1:(width==32)?2:0);
                /* cmp r11, rhs */
                const cs_x86_op *rhs = (op1 && (op1->type==X86_OP_REG||op1->type==X86_OP_IMM))
                                        ? op1 : NULL;
                if (!rhs) ABORT("cmp with unsupported rhs");
                t = emit_cmp_r11(t, rhs, op0->size);
            }
            /* ---------------- cmp  reg, [mem]  (opcode 0x3B) ---------------- */
            else if (tmp[0].id == X86_INS_CMP &&
                     op0->type == X86_OP_REG &&
                     op1 && op1->type == X86_OP_MEM)
            {
                DBG("cmp reg, [mem]");

                size_t cmp_width = op1->size;   /* width is in BYTES */

                t = emit_lea_r11(t, op1, tmp[0].address, tmp[0].size);
                t = emit_add_r11_imm(t, SHADOW_DELTA);

                cs_x86_op r11op = {
                    .type = X86_OP_REG,
                    .reg  = X86_REG_R11,
                    .size = cmp_width
                };

                t = emit_load_from_shadow(t, &r11op, cmp_width, 0, 0);
                t = emit_xor_with_mask(t, &r11op, cmp_width,
                                       (cmp_width == 16) ? 1 :
                                       (cmp_width == 32) ? 2 : 0);

                int dst_id = rm_id(op0);

                uint8_t rex = 0x40;
                if (cmp_width == 8) rex |= 0x08;   /* REX.W for 64-bit compare */
                if (dst_id & 8)     rex |= 0x04;   /* reg field */
                rex |= 0x01;                       /* r/m = r11 */
                *t++ = rex;

                *t++ = 0x3B;   /* cmp reg, r/m */
                *t++ = (uint8_t)(((dst_id & 7) << 3) | 0x03);
            }

            /* ---------------- XOR  reg, [mem]  (dst ^= *(addr)) ---------------- */
            else if (tmp[0].id == X86_INS_XOR &&
                    op0->type == X86_OP_REG &&
                    op1 && op1->type == X86_OP_MEM) {

                DBG("XOR reg, [mem] touching secret");

                int dst_is_scratch =
                    (op0->reg == X86_REG_R11 || op0->reg == X86_REG_R11D ||
                    op0->reg == X86_REG_R10 || op0->reg == X86_REG_R10D ||
                    op0->reg == X86_REG_RDI || op0->reg == X86_REG_EDI);

                if (dst_is_scratch) {
                    t = emit_xor_reg_mem_preserve_scratch(t, op0, mop, tmp[0].address, tmp[0].size, op0->size);
                } else {
                    /* r11 := shadow-address(addr) */
                    t = emit_lea_r11(t, mop, tmp[0].address, tmp[0].size);
                    t  = emit_add_r11_imm(t, SHADOW_DELTA);

                    /* r11 := plaintext value = load(addr)^mask */
                    cs_x86_op r11op = {
                        .type = X86_OP_REG,
                        .reg  = X86_REG_R11,
                        .size = op0->size
                    };
                    t = emit_load_from_shadow(t, &r11op, r11op.size, 0, 0);
                    t = emit_xor_with_mask(t, &r11op, r11op.size, 0);

                    /* dst ^= r11 */
                    uint8_t dst_id = rm_id(op0);
                    uint8_t rex    = 0x40;
                    if (r11op.size == 8)  rex |= 0x08;
                    if (dst_id & 8)       rex |= 0x01;
                    rex                  |= 0x04;
                    if (rex != 0x40)      *t++ = rex;

                    if (r11op.size == 2)  *t++ = 0x66;

                    *t++ = 0x31;
                    *t++ = 0xC0 | (3 << 3) | (dst_id & 7);
                }
            }

            /* ---------------- XOR  [mem], reg  (RMW) ---------------- */
            else if (tmp[0].id == X86_INS_XOR &&
                    op0->type == X86_OP_MEM &&
                    op1 && op1->type == X86_OP_REG) {
                DBG("XOR touching secret XOR [mem], reg (RMW)");

                size_t w = op0->size;

                cs_x86_op r10op = {
                    .type = X86_OP_REG,
                    .reg  = (w == 1) ? X86_REG_R10B :
                            (w == 2) ? X86_REG_R10W :
                            (w == 4) ? X86_REG_R10D : X86_REG_R10,
                    .size = w
                };

                t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);

                /* plaintext := load(shadow) ^ old_mask */
                t = emit_load_r10_from_r11(t, w);
                t = emit_xor_with_mask(t, &r10op, w, 0);

                /* plaintext ^= src_reg -- FLAGS ARE DEFINED HERE */
                t = emit_binop_r10_reg(t, 0x30 /* XOR */, op1, w);

                *t++ = 0x9C;   /* pushfq */

                /* refresh mask + re-mask + store */
                t = emit_refresh_mask_inline_aes(t, w);
                // t = emit_recompute_shadow_r11(t, mop, tmp[0].address, tmp[0].size);
                t = emit_xor_with_mask(t, &r10op, w, 0);
                t = emit_store_r10_to_r11(t, w);

                *t++ = 0x9D;   /* popfq */
            }

            /* ----- LEA touching secret: copy verbatim / relocate RIP-relative only ----- */
            else if (tmp[0].id == X86_INS_LEA) {
                DBG("LEA touching secret — copy verbatim");

                const cs_x86 *x = &tmp[0].detail->x86;
                const cs_x86_op *mop = NULL, *dop = NULL;
                for (int i = 0; i < x->op_count; i++) {
                    if (x->operands[i].type == X86_OP_MEM) mop = &x->operands[i];
                    if (x->operands[i].type == X86_OP_REG) dop = &x->operands[i];
                }
                if (!mop || !dop) ABORT("tail-copy LEA touching secret: missing operands");

                /* non-RIP-relative LEA must be copied exactly as-is */
                if (mop->mem.base != X86_REG_RIP) {
                    memcpy(t, (void *)tmp[0].address, tmp[0].size);
                    t += tmp[0].size;
                } else {
                    /* RIP-relative LEA must be relocated */
                    int dst_id = rm_id(dop);
                    bool dst_is_64 = (dop->size == 8);

                    uint8_t rex = 0x40;
                    if (dst_is_64)  rex |= 0x08;
                    if (dst_id & 8) rex |= 0x04;
                    if (rex != 0x40) *t++ = rex;

                    *t++ = 0x8D;
                    *t++ = (0 << 6) | ((dst_id & 7) << 3) | 5;   /* mod=00 rm=101 RIP-rel */

                    uint64_t target = effective_addr(uc, mop, tmp[0].address, tmp[0].size);
                    int32_t disp = (int32_t)(target - ((uint64_t)t + 4));
                    memcpy(t, &disp, 4);
                    t += 4;
                }
            }

            /* ---------------- MOVZX / MOVSX  reg, [mem] ---------------- */
            else if ((tmp[0].id == X86_INS_MOVZX || tmp[0].id == X86_INS_MOVSX || tmp[0].id == X86_INS_MOVSXD) &&
                    op0->type == X86_OP_REG &&
                    op1 && op1->type == X86_OP_MEM) {
                int sign = (tmp[0].id == X86_INS_MOVSX || tmp[0].id == X86_INS_MOVSXD);

                if (dest_is_scratch_and_src_is_mem(tmp)) {
                    DBG("tail MOVZX/MOVSX/MOVSXD reg,[mem] -> scratch-safe slow path");
                    t = emit_mov_reg_mem_preserve_scratch(t, op0, mop,
                                                        tmp[0].address, tmp[0].size,
                                                        op1->size, sign);
                } else {
                    t = emit_lea_r11(t, mop, tmp[0].address, tmp[0].size);
                    t = emit_add_r11_imm(t, SHADOW_DELTA);
                    t = emit_load_from_shadow(t, op0, op1->size, 0, sign);
                    t = emit_xor_with_mask(t, op0, width, (width==16)?1:(width==32)?2:0);
                }
            }
            /* -------- memory‑form NOP (0F 1F /0 etc.) -------------------- */
            else if (tmp[0].id == X86_INS_NOP) {
                memcpy(t, tmp[0].bytes, tmp[0].size);
                t += tmp[0].size;
            }
            else {
                ABORT("unhandled secret‐mem tail opcode 0x%x at 0x%llx",
                      tmp[0].id, (unsigned long long)(rip+ofs));
            }
            t = restore_regs(t, clobber, tail_preserve_flags);
        }

        DBG(" tail[%2zu] at 0x%" PRIx64 ": %s %s  → touches_secret=%d",ofs, tmp[0].address, tmp[0].mnemonic, tmp[0].op_str, touches_secret);
        ofs += tmp[0].size;
        cs_free(tmp, 1);
    }

    /* ----------------------------------------------------------------------------- */
    /*     Construct the end of trampoline, If we are not leaving the trampoline.    */
    /* ----------------------------------------------------------------------------- */
    if (!tail_is_terminal) {
        /*   jump back right after the stolen chunk   */
        /* ---- back-jump: tramp → (rip + steal) ---- */
        int64_t rel_back64 = (int64_t)((rip + steal) - ((uint64_t)t + 5));

        if (rel_back64 >= INT32_MIN && rel_back64 <= INT32_MAX) {
            DBG("[tramp] Plan A : 5-byte back-jmp   E9 rel32 = %d", (int32_t)rel_back64);
            /* Plan A : 5-byte  E9 rel32 */
            *t++ = 0xE9;
            back_dst_ptr = t;                 /* <-- remember position */
            back_is_rel32 = 1;
            int32_t rel32_tmp = (int32_t)rel_back64;
            memcpy(t, &rel32_tmp, 4); t += 4;
        } else {
            DBG("[tramp] Plan B : 14-byte back-jmp   abs-jmp to 0x%llx", (unsigned long long)(rip + steal));
            /* Plan B : 13-byte  movabs r11,imm64 ; jmp r11 */
            *t++ = 0x49; *t++ = 0xBB;          /* movabs r11, imm64 */
            back_dst_ptr = t;                  /* <-- remember imm64 */
            back_is_rel32 = 0;
            uint64_t imm_tmp = rip + steal;    /* provisional          */
            memcpy(t, &imm_tmp, 8);  t += 8;
            *t++ = 0x41; *t++ = 0xFF; *t++ = 0xE3;   /* jmp r11        */
        }
    }
    
    if ((size_t)(t - tramp) > tramp_len)
    ABORT("trampoline overflow at end: size=%zu cap=%zu",
          (size_t)(t - tramp), tramp_len);

    DBG("🏃  tramp @%p  size=%zu", tramp, (size_t)(t - tramp));
    DBG("tramp @%p →", tramp);
    #ifdef DEBUG
    {
        fprintf(stderr, "[%d:%d]   ", (int)getpid(), (int)TID);

        for (size_t i = 0; i < (size_t)(t - tramp); i++)
            fprintf(stderr, "%02x ", tramp[i]);

        fprintf(stderr, "\n");
        fprintf(stderr, "Trampoline Instructions");
        fprintf(stderr, "\n");
        dump_bytes_as_code(tramp, (size_t)(t - tramp), (uint64_t)tramp);
    }
    #endif


    /* ------------  patch original site with a jump to tramp --------- */
    int64_t rel = (int64_t)tramp - (int64_t)(rip + 5);
    DBG("[patch] rip=%p tramp=%p  rel=%lld (0x%llx)",
       (void*)rip, (void*)tramp,
       (long long)rel, (unsigned long long)rel);
    void   *page        = (void *)(rip & ~(pagesize() - 1));
    size_t  need_bytes  =   /* 5-byte E9 rel32  or 13-byte absolute */
            ((rel >= INT32_MIN && rel <= INT32_MAX) ? PATCH_REL32_LEN : PATCH_ABS_R11_LEN);
    /* ------- ensure we won’t overwrite partial instructions ------- */
    while (steal < need_bytes) {
        uintptr_t pc       = rip + steal;
        uintptr_t pg_end   = (pc & ~(pagesize() - 1)) + pagesize();
        size_t    max_len  = pg_end - pc;
        if (max_len > 15) max_len = 15;

        cs_insn *tmp;
        size_t n = cs_disasm(cs, (uint8_t *)pc, max_len, pc, 1, &tmp);
        if (n != 1)
            ABORT("decode while extending steal");

        memcpy(orig + steal, tmp[0].bytes, tmp[0].size);
        steal += tmp[0].size;
        cs_free(tmp, 1);
    }
    if (steal < need_bytes) ABORT("steal (%zu) < patch bytes (%zu)", steal, need_bytes);

    /* offset of RIP inside its page */
    size_t  off_in_page = (size_t)rip & (pagesize() - 1);

    /* total span of bytes we will overwrite, rounded up to full pages */
    size_t  span        = off_in_page + need_bytes;
    span                = (span + pagesize() - 1) & ~(pagesize() - 1);

    /* make every touched page RWX */
    mprotect(page, span, PROT_READ | PROT_WRITE | PROT_EXEC);

    if (rel >= INT32_MIN && rel <= INT32_MAX) {
        DBG("[patch] Plan A (5-byte E9) – rel fits in int32");
        /* ---------------- Plan A : 5-byte  E9 rel32 ---------------- */
        uint8_t jmp5[5] = { 0xE9 };
        int32_t rel32 = (int32_t)rel;
        memcpy(jmp5 + 1, &rel32, 4);
        memcpy((void *)rip, jmp5, 5);

        /* pad any extra stolen bytes with NOPs */
        if (steal > 5)
            memset((uint8_t *)rip + 5, 0x90, steal - 5);

    } else {
        DBG("[patch] Plan B (13-byte abs-jmp) – rel outside int32");
        /* ---------------- Plan B : 13-byte absolute jump ------------ */
        /* layout: 49 BB imm64         mov r11, imm64
                41 FF E3            jmp r11      */
        uint8_t jmp_abs[PATCH_ABS_R11_LEN] = { 0x49, 0xBB };
        memcpy(jmp_abs + 2, &tramp, 8);             /* imm64 */
        jmp_abs[10] = 0x41;
        jmp_abs[11] = 0xFF;
        jmp_abs[12] = 0xE3;

        /* ensure we have at least 13 bytes; steal more if necessary */
        while (steal < PATCH_ABS_R11_LEN) {
            /* compute how many bytes we can safely read from rip+steal */
            uintptr_t pc      = rip + steal;
            uintptr_t page_end = (pc & ~(pagesize()-1)) + pagesize();
            size_t    max_len = page_end - pc;
            if (max_len > 15) max_len = 15;

            cs_insn *tmp;
            size_t   n = cs_disasm(cs,
                                (uint8_t *)pc,   /* decode next bytes */
                                max_len,         /* up to a full 15B */
                                pc,
                                1, &tmp);
            if (n != 1) ABORT("decode while extending steal");
            memcpy(orig + steal, tmp[0].bytes, tmp[0].size);   /* save them */
            steal += tmp[0].size;
            cs_free(tmp, 1);
        }

        memmove((void *)rip, jmp_abs, PATCH_ABS_R11_LEN);   /* write patch */

        if (steal > PATCH_ABS_R11_LEN)
            memset((uint8_t *)rip + PATCH_ABS_R11_LEN, 0x90, steal - PATCH_ABS_R11_LEN);
    }

    #ifdef DEBUG
    {
        fprintf(stderr, "\nPatched Instructions\n");
        // dump_code_around(rip, 2,2);
        dump_code(rip, 32);
    }
    #endif

    /* ------------------------------------------------------------------ */
    /*     Final‑fix the return jump, now that `steal` is definitive      */
    /* ------------------------------------------------------------------ */
    if (back_dst_ptr) {
        uint64_t new_target = rip + steal;

        if (back_is_rel32) {
            int32_t rel32 = (int32_t)((int64_t)new_target -
                                    ((int64_t)back_dst_ptr + 4));
            memcpy(back_dst_ptr, &rel32, 4);
        } else {
            memcpy(back_dst_ptr, &new_target, 8);
        }
    }                
    
    __builtin___clear_cache((char *)rip, (char *)rip + steal);
    mprotect(tramp, tramp_len, PROT_READ | PROT_EXEC);   /* RX only */
    mprotect(page, span, PROT_READ | PROT_EXEC);

    /* -------------------------------------------------------------- */
    /*                       Remember patch                           */
    /* -------------------------------------------------------------- */
    p->orig_len = steal;
    p->tramp    = tramp;
    HASH_ADD(hh, patches, rip, sizeof(rip), p);

    cs_free(ins, 1);
    /* return → re-execute -> JMP tramp  */
}


/* ---------------- alternate signal stack ---------------- */
static uint8_t *alt_stack_mem = NULL;
/* ---------------- constructor --------------------------- */
__attribute__((constructor))
static void init(void)
{
    /*  Set up Capstone */
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK)
        die("cs_open");
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    /*  Allocate a *dedicated* RW buffer for the alt-stack */
    alt_stack_mem = mmap(NULL, ALT_STACK_SZ,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (alt_stack_mem == MAP_FAILED) die("mmap alt_stack");
    
    /*  Install an alternate signal stack */
    {
        stack_t ss = {
            .ss_sp    = alt_stack_mem,
            .ss_size  = ALT_STACK_SZ,
            .ss_flags = 0
        };
        if (sigaltstack(&ss, NULL) == -1)
            die("sigaltstack");
    }

    struct sigaction sa={0};
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sa.sa_sigaction = sigsegv;
    sigaction(SIGSEGV, &sa, NULL);

    DBG("[Signal-2] shadow-trampoline ready\n");
}