// gcc -shared -fPIC -o PDM-encrypt.so PDM-encrypt.c -g -O0 -fno-omit-frame-pointer -fno-stack-protector -lcapstone -pthread -ldl -DPDM_MASKING=1


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

#define ALT_STACK_SZ   (64 * 1024)
#define PAGE_SZ  4096

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


#ifndef PDM_MASKING
/* Build with:
 *   -DPDM_MASKING=0   (disable masking; shadow holds plaintext)
 *   -DPDM_MASKING=1   (enable masking; shadow holds XOR-masked bytes)
 */
#define PDM_MASKING 0
#endif

#if PDM_MASKING
#  define PDM_MASK_BYTE 0xA5
#  define PDM_MASK16    0xA5A5
#  define PDM_MASK32    0xA5A5A5A5U
#  define PDM_MASK64    0xA5A5A5A5A5A5A5A5ULL
#else
#  define PDM_MASK_BYTE 0x00
#  define PDM_MASK16    0x0000
#  define PDM_MASK32    0x00000000U
#  define PDM_MASK64    0x0000000000000000ULL
#endif


/* ---------------  Protected Address in the victim --------------------- */
static char  *secret;
static size_t secret_len;

static char  *encrypted_secret = NULL;   /* shadow – allocated on demand */
static char  *secret_mask_page = NULL;   /* mask  – allocated on demand  */
static int    g_pkey           = -1;
extern  bool  disable_secret;            /* set by victim argv (1 / 2)   */

/* -------------------------------------------------------- */
/* --------------- Other Global Vars ---------------------- */
int counter  = 0;
static csh cs;      /* Capstone handle (global) */
static int64_t SHADOW_DELTA;
static int64_t MASK_DELTA;          /*   secret_mask_page – encrypted_secret  */
/* -------------------------------------------------------- */

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

static void dump2(const char *lbl, const uint8_t *p, size_t n)
{
    // printf("%s @%p :", lbl, p);
    printf("%s :", lbl);
    for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
    puts("");
}
void install_guard(void *addr, size_t len)
{
    if (!addr || len == 0) return;

    /* ── 1. round down to page boundary, round up the length ───────── */
    const size_t  PAGE = (size_t)sysconf(_SC_PAGESIZE);   /* 4096 */
    uintptr_t base     = (uintptr_t)addr & ~(PAGE - 1);    /* page-aligned */
    size_t    offset   = (uintptr_t)addr - base;           /* inside page  */
    size_t    plen     = (len + offset + PAGE - 1) & ~(PAGE - 1);

    secret      = (char *)base;
    secret_len  = plen;

    /* ── 2. allocate mask + shadow exactly “plen” bytes  ───────────── */
    secret_mask_page = mmap(NULL, plen, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    encrypted_secret = mmap(NULL, plen, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (secret_mask_page == MAP_FAILED || encrypted_secret == MAP_FAILED)
        perror("mmap"), exit(1);
    SHADOW_DELTA = (int64_t)encrypted_secret - (int64_t)secret;
    MASK_DELTA   = (int64_t)secret_mask_page - (int64_t)encrypted_secret;

    for (size_t i = 0; i < plen; i++) {
        uint8_t b = ((uint8_t *)secret)[i];
        secret_mask_page[i] = (char)PDM_MASK_BYTE;
        encrypted_secret[i] = (char)(b ^ PDM_MASK_BYTE);
        secret[i] = encrypted_secret[i];
    }
    dump2("[victim] secret AFTER guarding", (uint8_t*)secret, 98);

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
    uint64_t rip;
    uint8_t  orig_len;
    uint8_t *tramp;
    UT_hash_handle hh;
} patch_t;
static patch_t *patches = NULL;

/* ---------------- little helpers ------------------------ */
static long pagesize(void) { static long p=0; if(!p) p=sysconf(_SC_PAGESIZE); return p; }
static void die(const char *m){ perror(m); exit(1); }


// Saves: R8, RDI, R11, R10 (unless masked out).
// If preserve_flags == 0: we also save/restore RFLAGS around the scratch frame.
// If preserve_flags != 0: we DO NOT touch RFLAGS (for TEST+Jcc paths).
static inline uint8_t *save_regs(uint8_t *t, int mask, int preserve_flags)
{
    if (!preserve_flags) {
        // pushfq
        // *t++ = 0x9C;
    }

    // sub rsp, 0xA0   (scratch area)
    *t++ = 0x48; *t++ = 0x81; *t++ = 0xEC;
    *t++ = 0xA0; *t++ = 0x00; *t++ = 0x00; *t++ = 0x00;

    // Layout:
    // [rsp+0x00] = r8
    // [rsp+0x08] = rdi
    // [rsp+0x10] = r11
    // [rsp+0x18] = r10
    if (!(mask & 8)) {           // r8 -> [rsp]
        *t++ = 0x4C; *t++ = 0x89; *t++ = 0x04; *t++ = 0x24;
    }
    if (!(mask & 1)) {           // rdi -> [rsp+8]
        *t++ = 0x48; *t++ = 0x89; *t++ = 0x7C; *t++ = 0x24; *t++ = 0x08;
    }
    if (!(mask & 2)) {           // r11 -> [rsp+0x10]
        *t++ = 0x4C; *t++ = 0x89; *t++ = 0x5C; *t++ = 0x24; *t++ = 0x10;
    }
    if (!(mask & 4)) {           // r10 -> [rsp+0x18]
        *t++ = 0x4C; *t++ = 0x89; *t++ = 0x54; *t++ = 0x24; *t++ = 0x18;
    }

    return t;
}

static inline uint8_t *restore_regs(uint8_t *t, int mask, int preserve_flags)
{
    if (!(mask & 4)) {           // r10 <- [rsp+0x18]
        *t++ = 0x4C; *t++ = 0x8B; *t++ = 0x54; *t++ = 0x24; *t++ = 0x18;
    }
    if (!(mask & 2)) {           // r11 <- [rsp+0x10]
        *t++ = 0x4C; *t++ = 0x8B; *t++ = 0x5C; *t++ = 0x24; *t++ = 0x10;
    }
    if (!(mask & 1)) {           // rdi <- [rsp+0x08]
        *t++ = 0x48; *t++ = 0x8B; *t++ = 0x7C; *t++ = 0x24; *t++ = 0x08;
    }
    if (!(mask & 8)) {           // r8 <- [rsp]
        *t++ = 0x4C; *t++ = 0x8B; *t++ = 0x04; *t++ = 0x24;
    }

    // IMPORTANT: use LEA for stack adjust so flags are not touched.
    // lea rsp, [rsp + 0xA0]
    *t++ = 0x48; *t++ = 0x8D; *t++ = 0xA4; *t++ = 0x24;
    *t++ = 0xA0; *t++ = 0x00; *t++ = 0x00; *t++ = 0x00;

    if (!preserve_flags) {
        // popfq
        // *t++ = 0x9D;
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
    /* quick screen-out: instructions with no memory operand */
    int have_mem = 0;
    for (int i = 0; i < x->op_count; i++)
        if (x->operands[i].type == X86_OP_MEM) { have_mem = 1; break; }
    if (!have_mem) return 0;

    /* opcode-based check (works with all Capstone versions) */
    switch (ci->id) {
        case X86_INS_MOV:
        case X86_INS_MOVSB: case X86_INS_MOVSW:
        case X86_INS_MOVSD: case X86_INS_MOVSQ:
        case X86_INS_STOSB: case X86_INS_STOSW:
        case X86_INS_STOSD: case X86_INS_STOSQ:
        case X86_INS_CMPSB: case X86_INS_CMPSW:
        case X86_INS_CMPSD: case X86_INS_CMPSQ:
        case X86_INS_SCASB: case X86_INS_SCASW:
        case X86_INS_SCASD: case X86_INS_SCASQ:
        case X86_INS_XCHG:
        case X86_INS_ADD:  case X86_INS_SUB:
        case X86_INS_INC:  case X86_INS_DEC:
        case X86_INS_XOR:  case X86_INS_OR:
        case X86_INS_AND:
        case X86_INS_VMOVDQA:
        case X86_INS_VMOVDQU:
        /* …anything else we treat specially… */
            /* destination is operand 0 for all of the above */
            if (x->operands[0].type == X86_OP_MEM)
                return 1;
            return 0;
        default:
            return 0;
    }
}

// --- record our main thread’s stack once, in a signal-safe context ---
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

/* try to reserve RWX memory within ±2 GiB of rip */
static void *alloc_near(uint64_t rip, size_t len)
{
    /* start 1.5 GiB below RIP, step… */
    const uint64_t window = 0x60000000ULL;      // 1.5 GiB
    uint64_t lo = (rip > window) ? rip - window : 0x10000;
    lo &= ~(pagesize() - 1);      // round down
    uint64_t hi = rip + window;

    for (uint64_t addr = lo; addr < hi; addr += 0x10000) {
        /* skip our saved stack region */
        if ((void*)addr >= stack_base &&
            (void*)addr <  (void*)((char*)stack_base + stack_size))
            continue;
        void *p = mmap((void *)addr, len,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS |
                       MAP_FIXED_NOREPLACE,       /* don’t clobber anything */
                       -1, 0);
        if (p != MAP_FAILED)
            return p;            /* got one! */
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
    /* ------------- low eight ------------------------------------------------ */
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

/* given ucontext + Capstone mem-operand → return absolute EA           */
static uint64_t effective_addr(const ucontext_t *uc, const cs_x86_op *mem,
                               uint64_t ins_rip)
{
    uint64_t base   = 0, index = 0;

    if (mem->mem.base  != X86_REG_INVALID)
        base  = uc->uc_mcontext.gregs[ greg_for(mem->mem.base) ];
    if (mem->mem.index != X86_REG_INVALID)
        index = uc->uc_mcontext.gregs[ greg_for(mem->mem.index) ];

    /* RIP-relative is encoded as base==RIP in Capstone */
    if (mem->mem.base == X86_REG_RIP)
        base = ins_rip + mem->mem.disp;                /* disp already sign-extended */

    return base + index * mem->mem.scale +
           (mem->mem.base == X86_REG_RIP ? 0 : mem->mem.disp);
}


// Debug helper: disassemble and print the instruction at RIP.
void print_instruction(unsigned long rip) {
    unsigned char code[16] = {0};
    memcpy(code, (void *)rip, sizeof(code));
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        DBG("[ERROR] Failed to initialize Capstone\n");
        return;
    }
    cs_insn *insn;
    size_t count = cs_disasm(handle, code, sizeof(code), rip, 1, &insn);
    if (count > 0) {
        DBG("Faulting instruction at 0x%lx: %s %s (size: %u bytes)\n",
                rip, insn[0].mnemonic, insn[0].op_str, insn[0].size);
        cs_free(insn, count);
    } else {
        DBG("Failed to disassemble instruction at 0x%lx\n", rip);
    }
    cs_close(&handle);
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

/* ------------------------------------------------------------------ */
/* Disassemble N instructions before and after `rip` and highlight it */
/* ------------------------------------------------------------------ */
static void dump_code_around(uint64_t rip, int before, int after)
{
    const size_t PAGE     = pagesize();                  /* 4 KiB                         */
    const uintptr_t plo   = rip & ~(PAGE - 1);           /* page start that holds <rip>   */
    const uintptr_t phi   = plo + PAGE;                  /* first byte of next page       */

    /* pessimistic “bytes we might need”                        */
    size_t want_back = before * 15 + 16;                 /* 15 B worst-case insn + pad    */
    size_t want_fwd  = after  * 15 + 16;

    /* clamp to the page actually mapped                         */
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



/**********************************************************************************************************************************************************************************/
/**********************************************************************************************************************************************************************************/
/**********************************************************************************************************************************************************************************/
/* ------------------------------------------------------------------ */
/* Emit “lea r11,[mem]” – where `mem` is the *original* Capstone       */
/* memory operand of the faulting/stolen instruction.                 */
/* Returns updated pointer.  Uses NO other registers.                  */
static uint8_t *emit_lea_r11(uint8_t *p, const cs_x86_op *mem,
                             uint64_t orig_rip_of_insn)
{
    /* ----------------------------------------------------------------
       We must rebuild exactly the ModRM/SIB the CPU decoded originally.
       Rules:
         *   base  and index  come from mem->mem.{base,index}
         *   disp  is mem->mem.disp (already sign‑extended to 64 b)
         *   scale is mem->mem.scale (1,2,4,8)
       For RIP‑relative (base == RIP) we can keep the old behaviour
       (it is already constant) – so just               movabs r11, EA .
       ----------------------------------------------------------------*/
    if (mem->mem.base == X86_REG_RIP) {
        uint64_t ea = orig_rip_of_insn + mem->mem.disp;
        *p++ = 0x49; *p++ = 0xBB;                /* movabs r11, imm64 */
        memcpy(p, &ea, 8); p += 8;
        return p;
    }

    /* -------- build REX prefix ----------------------------------- */
    uint8_t rex = 0x4C;                  /* 0100 | W=1 | R=1 | X=0 | B=0
                                            W=1 (64‑bit), R selects r11
                                            X/B will be patched below   */
    int base = rm_id(&(cs_x86_op){ .type = X86_OP_REG, .reg  = mem->mem.base });               /* id for base register        */
    int index= -1;
    if (mem->mem.index != X86_REG_INVALID)
        index = rm_id(&(cs_x86_op){.type=X86_OP_REG,.reg=mem->mem.index});
    if (base & 8)  rex |= 0x01;          /* B bit */
    if (index>=0 && (index & 8)) rex |= 0x02;   /* X bit */
    if (rex != 0x40) *p++ = rex;

    /* -------- LEA opcode + ModRM/SIB/disp ------------------------ */
    *p++ = 0x8D;                         /* LEA r/m64 -> r64            */

    /* decide whether we need a SIB byte */
    int need_sib = (mem->mem.index != X86_REG_INVALID) ||
                   (base & 7) == 4 /*RSP*/ || (base & 7) == 5 /*RBP*/;

    /* ---------------- ModRM ------------------------------------- */
    uint8_t modrm = 0;
    uint8_t disp_size = 0;
    if (mem->mem.disp == 0 &&
        (base & 7) != 5) {               /* no disp, base≠RBP */
        modrm = 0x00;                    /* [base]               */
    } else if ((int32_t)mem->mem.disp == mem->mem.disp) {
        modrm = 0x80; disp_size = 4;     /* disp32               */
    } else {                             /* disp8 impossible – huge disp */
        modrm = 0x80; disp_size = 4;
    }
    modrm |= (3 /*r11*/ & 7) << 3;       /* reg field            */
    modrm |= need_sib ? 4 : (base & 7);  /* r/m field            */
    *p++ = modrm;

    /* ---------------- SIB (if any) ------------------------------- */
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

    /* ---------------- displacement --------------------------------*/
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
    {
        uint8_t *end = p;
        int32_t disp;

        disp = (int32_t)(end - (skip_low + 4));
        memcpy(skip_low, &disp, 4);

        disp = (int32_t)(end - (skip_high + 4));
        memcpy(skip_high, &disp, 4);
    }
    return p;
}

/* ---- emit “cmp r11, immXX / reg” ------------------------------------ */
static inline uint8_t *emit_cmp_r11(uint8_t *t,
                                    const cs_x86_op *rhs,   /* IMM or REG */
                                    size_t width)           /* 1/2/4/8    */
{
    if (rhs->type == X86_OP_IMM) {
        /* choose shortest encoding that fits */
        if (width == 1) {                 /* cmp r11b, imm8 */
            *t++ = 0x41; *t++ = 0x80; *t++ = 0xFB;
            *t++ = (uint8_t)rhs->imm;
        } else if (width == 2) {          /* cmp r11w, imm16 */
            *t++ = 0x66; *t++ = 0x41; *t++ = 0x81; *t++ = 0xFB;
            uint16_t v = (uint16_t)rhs->imm; memcpy(t, &v, 2); t += 2;
        } else {                          /* width 4 or 8 → imm32 works */
            *t++ = 0x41; *t++ = 0x81; *t++ = 0xFB;
            uint32_t v = (uint32_t)rhs->imm; memcpy(t, &v, 4); t += 4;
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

/* ------------------------------------------------------------------ */
/*  Emit:  xor  [<baseReg>], imm{8,16,32} / imm32 (sign‑extended)     */
/*  `base_id` is the ModRM r/m code 0‑15 (use rm_id()).               */
/*  Width must be 1,2,4 or 8.                                         */
/*  Returns updated pointer.                                          */
/* ------------------------------------------------------------------ */
static uint8_t *emit_xor_mem_imm(uint8_t *p,
                                 int base_id,      /* 0‑15, eg RDI=7, R11=3 */
                                 size_t width,
                                 uint64_t imm)
{
    /* -------- REX prefix ----------------------------------------- */
    uint8_t rex = 0x40;             /* 0100 WRXB */
    if (width == 8)  rex |= 0x08;   /* W=1 for 64‑bit variant */
    if (base_id & 8) rex |= 0x01;   /* B=high bit of r/m      */
    if (rex != 0x40) *p++ = rex;

    /* -------- operand‑size prefix (16‑bit only) ------------------ */
    if (width == 2) *p++ = 0x66;

    /* -------- opcode + ModRM ------------------------------------- */
    if (width == 1) {
        *p++ = 0x80;                /* 80 /6 ib */
    } else {
        *p++ = 0x81;                /* 81 /6 iw/ id */
    }
    *p++ =        (6 << 3) | (base_id & 7);   /* mod = 00 → memory */

    /* -------- immediate ------------------------------------------ */
    if (width == 1) {
        *p++ = (uint8_t)imm;
    } else if (width == 2) {
        uint16_t v = (uint16_t)imm; memcpy(p,&v,2); p += 2;
    } else {                        /* 32‑ or 64‑bit width → imm32 sign‑ext */
        uint32_t v = (uint32_t)imm; memcpy(p,&v,4); p += 4;
    }
    return p;
}


#define PAGE_MASK (~(PAGE_SZ - 1))
static inline void make_page_rwx(void *addr)
{
    void *page = (void *)((uintptr_t)addr & PAGE_MASK);
    /* Ignore errors: page might already be RWX. */
    mprotect(page, PAGE_SZ, PROT_READ | PROT_WRITE | PROT_EXEC);
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
    uint64_t lo = (uint64_t)encrypted_secret;
    uint64_t hi = lo + secret_len;

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


/* ────────────────────────────────────────────────────────────────── */
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


    /* ───────── scalar GPRs ───────── */
    const int dst_is_r10 = dst->reg == X86_REG_R10 || dst->reg == X86_REG_R10D;
    /* Skip the XOR when the EA is *not* inside the secret page -------- */
    uint8_t *skip_low = NULL, *skip_high = NULL;
    p = emit_branch_if_not_secret(p, &skip_low, &skip_high, !dst_is_r10);

    uint8_t id  = rm_id(dst);

    /* ---- 64‑bit registers: load full mask into a scratch and XOR ---- */
    if (width == 8) {

        /* Load mask into src_reg = r10 (normal) or r8 (if dst is r10). */
        const int mask_src_is_r8 = dst_is_r10;
        if (mask_src_is_r8) {                   /* movabs r8, mask */
            *p++ = 0x49; *p++ = 0xB8;
        } else {                                /* movabs r10, mask */
            *p++ = 0x49; *p++ = 0xBA;
        }
        uint64_t m64 = PDM_MASK64;
        memcpy(p, &m64, 8); p += 8;

        /* xor dst, mask_src */
        uint8_t dst_id = id;                    /* rm_id(dst) from above */
        uint8_t src_id = mask_src_is_r8 ? 8 : 10;   /* r8 or r10 */
        uint8_t rex = 0x48;                     /* REX.W */
        if (src_id & 8) rex |= 0x04;            /* R bit selects src */
        if (dst_id & 8) rex |= 0x01;            /* B bit selects dst */
        *p++ = rex;
        *p++ = 0x31;                            /* XOR r/m, reg */
        *p++ = 0xC0 | ((src_id & 7) << 3) | (dst_id & 7);

       goto patch_branches;
    }

    /* ---- 1/2/4‑byte registers: old code ---- */
    uint8_t rex = 0x40;
    if (id & 8)     rex |= 0x01;
    if (width == 2) *p++ = 0x66;
    if (rex != 0x40) *p++ = rex;

    if (width == 1) {                   /* 8‑bit */
        *p++ = 0x80;                    /* XOR r/m8, imm8  */
        *p++ = 0xF0 | (id & 7);
        *p++ = (uint8_t)PDM_MASK_BYTE;
    } else if (width == 2) {            /* 16‑bit */
        *p++ = 0x81;                    /* XOR r/m16, imm16 */
        *p++ = 0xF0 | (id & 7);
        uint16_t imm16 = (uint16_t)PDM_MASK16;
        memcpy(p,&imm16,2);  p += 2;
    } else {                            /* 32‑bit */
        *p++ = 0x81;                    /* XOR r/m32, imm32 */
        *p++ = 0xF0 | (id & 7);
        uint32_t imm32 = (uint32_t)PDM_MASK32;
        memcpy(p,&imm32,4);  p += 4;
    }

patch_branches:
    {
        uint8_t *end = p;
        int32_t rel;
        rel = (int32_t)(end - (skip_low  + 4));  memcpy(skip_low , &rel, 4);
        rel = (int32_t)(end - (skip_high + 4));  memcpy(skip_high, &rel, 4);
    }
    return p;
    #endif
}


static inline uint8_t *emit_mov_dst_from_r11(uint8_t *t, const cs_x86_op *dst)
{
    if (dst->type != X86_OP_REG) ABORT("LEA dst not a reg");
    int id = rm_id(dst);
    if (id < 0) ABORT("LEA dst bad reg");

    size_t width = dst->size;              /* bytes: 2,4,8 are valid for LEA */

    /* REX: 0100WRXB
       64-bit LEA dest → W=1
       R = high bit of dest
       B = 1 because r/m = r11 (high register) */
    uint8_t rex = 0x40;
    if (width == 8) rex |= 0x08;           /* W */
    if (id & 8)     rex |= 0x04;           /* R */
                     rex |= 0x01;          /* B for r11 */
    if (rex != 0x40) *t++ = rex;
    if (width == 2)  *t++ = 0x66;          /* 16-bit operand size */

    /* MOV r{16/32/64}, r/m{16/32/64} with r/m = r11 (mod=11, rm=3) */
    *t++ = 0x8B;
    *t++ = (uint8_t)(0xC0 | ((id & 7) << 3) | 0x03);  /* reg=dest, rm=r11 */
    return t;
    
}

/**********************************************************************************************************************************************************************************/
/**********************************************************************************************************************************************************************************/
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
        /* fast‑path: EA already lives in r11
        * ──────────────────────────────────
        * 1.  Copy it to RDI so loads/stores share the same base register.
        * 2.  Emit the width‑ / sign‑specific load directly into the *real*
        *     destination register (dst->reg).  No detour through r11d.
        */
            /* -- step‑1 : rdi ← r11 ------------------------------------- */
            *p++ = 0x4C; *p++ = 0x89; *p++ = 0xDF;        /* mov rdi,r11 */

            /* -- step‑2 : width/sign‑aware load dst,[rdi] --------------- */
            uint8_t id = rm_id(dst);
            if (id == (uint8_t)-1) ABORT("emit_load_from_shadow: bad dst reg");

            uint8_t rex = 0x40;                          /* 0100WRXB        */
            if (width == 8) rex |= 0x08;                 /* W               */
            if (id & 8)   rex |= 0x04;                   /* R (dst high bit)*/
            if (rex != 0x40) *p++ = rex;
            if (width == 2) *p++ = 0x66;                 /* 16‑bit prefix   */

            if (width == 1 || width == 2) {
                /* MOVZX / MOVSX variants */
                *p++ = 0x0F;
                *p++ = (width == 1
                        ? (sign_extend ? 0xBE : 0xB6)  /* byte  */
                        : (sign_extend ? 0xBF : 0xB7));/* word  */
            } else {                                     /* width 4 / 8     */
                *p++ = 0x8B;                             /* plain MOV       */
            }
            /* ModRM: reg = dst_id, rm = 7 (rdi) */
            *p++ = 0x07 | ((id & 7) << 3);

            return p;   /* value is *already* in dst – skip the old r11‑copy path */
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

/* ------------------------------------------------------------- */

copy_to_dst:

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

/**********************************************************************************************************************************************************************************/

static uint8_t *emit_store_to_shadow(uint8_t *p,
                                     const cs_x86_op *src,  /* source register */
                                     size_t width,
                                     uint64_t dst_abs)
{
    /* fast‑path: caller left the shadow address in R11.
       Vector stores need it in RDI, scalar stores keep it in R11. */
    if (dst_abs == 0) {
        /* mov rdi, r11  (two‑byte encoding: 4C 89 DF) */
        *p++ = 0x4C; *p++ = 0x89; *p++ = 0xDF;
        goto have_ptr_in_r11;
    }

    /* rdi = shadow_addr                                           */
    *p++ = 0x48; *p++ = 0xBF;
    memcpy(p,&dst_abs,8); p+=8;

    /* ----- emit the width-specific store ----------------------- */
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

        /* scalar 8-byte store: [rdi] ← <src_reg>   then  xor  <src_reg>, r10 */
        if (width == 8) {
            uint8_t rex;

        #if !PDM_MASKING
            /* Plain shadow: store [rdi] <- src */
            rex = 0x48;                      /* REX.W */
            if (id & 8) rex |= 0x04;         /* REX.R if src is r8..r15 */
            *p++ = rex;
            *p++ = 0x89;                     /* MOV r/m64, r64 */
            *p++ = 0x07 | ((id & 7) << 3);   /* ModRM: [rdi], src */
            return p;

        #else
            /* Masked shadow: store [rdi] <- (src ^ mask) without clobbering src.
            Use r10/r11 as scratch. Pick tmp != src. Use the other as mask reg. */

            uint8_t tmp    = (id == 10) ? 11 : 10;   /* tmp = r11 if src=r10 else r10 */
            uint8_t maskr  = (tmp == 10) ? 11 : 10;  /* mask reg is the other one */

            /* 1) mov tmp, src   (MOV r64, r/m64) */
            rex = 0x48;                               /* REX.W */
            if (tmp & 8) rex |= 0x04;                 /* REX.R for dst */
            if (id  & 8) rex |= 0x01;                 /* REX.B for src */
            *p++ = rex;
            *p++ = 0x8B;
            *p++ = 0xC0 | ((tmp & 7) << 3) | (id & 7);

            /* 2) movabs maskr, PDM_MASK64 */
            *p++ = 0x49;                              /* REX.W + B=1 (select r8..r15) */
            *p++ = 0xB8 + (maskr & 7);                /* mov r{8..15}, imm64 */
            uint64_t m64 = (uint64_t)PDM_MASK64;
            memcpy(p, &m64, 8); p += 8;

            /* 3) xor tmp, maskr   (XOR r/m64, r64) : dest=tmp (r/m), src=maskr (reg) */
            rex = 0x48;                               /* REX.W */
            if (maskr & 8) rex |= 0x04;               /* REX.R for reg field */
            if (tmp   & 8) rex |= 0x01;               /* REX.B for r/m field */
            *p++ = rex;
            *p++ = 0x31;
            *p++ = 0xC0 | ((maskr & 7) << 3) | (tmp & 7);

            /* 4) mov [rdi], tmp   (MOV r/m64, r64) */
            rex = 0x48;                               /* REX.W */
            if (tmp & 8) rex |= 0x04;                 /* REX.R if tmp is r8..r15 */
            *p++ = rex;
            *p++ = 0x89;
            *p++ = 0x07 | ((tmp & 7) << 3);           /* ModRM: [rdi], tmp */

            return p;
        #endif
        }

        else if (width == 4) {
            uint8_t rex = 0x40;                 /* W=0              */
            if (id & 8) rex |= 0x04;            /* high bit in R    */
            if (rex != 0x40) *p++ = rex;
            *p++ = 0x89;                        /* mov [rdi], src   */
        }
        else if (width == 2) {
            uint8_t rex = 0x40;
            if (id & 8) rex |= 0x04;
            if (rex != 0x40) *p++ = rex;
            *p++ = 0x66;                        /* operand‑size     */
            *p++ = 0x89;
        }
        else {                                  /* width == 1 */
            uint8_t rex = 0x40;                 /* bare REX */
            if (id & 8) rex |= 0x04;            /* high bit into R */
            /* 8‑bit regs other than AL/CL/DL/BL need *some* REX prefix.
               A redundant 0x40 is harmless for the old regs, so just emit it. */
            *p++ = rex;                         /* ALWAYS emit for byte ops */

            *p++ = 0x88;                        /* mov byte [rdi], src */
        }

        *p++ = 0x07 | ((id & 7) << 3); 
    }

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

/* Conditionally redirect r11 from secret -> shadow.
   Uses ONLY r8 as temp */
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


static inline bool has_rep_prefix(const cs_insn *ins)
{
    const uint8_t *p = ins->detail->x86.prefix;
    for (int i = 0; i < 4; i++) {
        if (p[i] == 0xF3 || p[i] == 0xF2) return true;
    }
    return false;
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

    /* --------  .Ltest:  test rcx,rcx ;  jz .Lend  -------- */
    uint8_t *lbl_test = t;
    *t++ = 0x48; *t++ = 0x85; *t++ = 0xC9;           /* test rcx, rcx      */
    *t++ = 0x0F; *t++ = 0x84;                        /* jz  rel32 (.Lend)  */
    uint8_t *jmp_to_end = t;  t += 4;                /* <-- patch later    */

    /* --------  .Lloop  ---------------------------------- */
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

        t = emit_load_r10_from_r11(t, width);        /* r10 = [src] (maybe masked) */
        t = emit_xor_with_mask(t, &valreg, width, 0);/* unmask -> plaintext */

        /* ---- DEST SECOND ---- */
        *t++ = 0x4C; *t++ = 0x8D; *t++ = 0x1F;                  /* lea r11,[rdi] */
        t = emit_maybe_shadow_r11(t, secret_base_abs, secret_end_abs);
        /* r11 now = effective dest (possibly shadow); r8 again scratch */

        t = emit_xor_with_mask(t, &valreg, width, 0);/* re-mask for shadow store */
        t = emit_store_r10_to_r11(t, width);         /* [dest] = r10 */
    } else {
        /* ---- DEST first ---- */
        *t++ = 0x4C; *t++ = 0x8D; *t++ = 0x1F;                  /* lea r11,[rdi] */
        t = emit_maybe_shadow_r11(t, secret_base_abs, secret_end_abs);

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


    /* --------  ++RSI / ++RDI  (DF=0 only)  ---------------- */
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

    /* --  RCX-- ;  jnz .Lloop  ------------------------------ */
    *t++ = 0x48; *t++ = 0xFF; *t++ = 0xC9;                      /* dec rcx     */
    *t++ = 0x0F; *t++ = 0x85;                                    /* jnz rel32   */
    {
        int32_t rel = (int32_t)(lbl_loop - (t + 4));
        memcpy(t, &rel, 4);  t += 4;
    }

    /* --------  .Lend: patch earlier JZ  -------------------- */
    {
        int32_t rel = (int32_t)(t - (jmp_to_end + 4));
        memcpy(jmp_to_end, &rel, 4);
    }
    return t;
}


static uint8_t* emit_or_mem_imm(uint8_t *p, uint8_t rm, size_t width, uint64_t imm) {
    // 1) REX prefix if needed
    uint8_t rex = 0x40
                | ((width == 8)   ? 0x08 : 0)   // W
                | ((rm     & 8)   ? 0x01 : 0);  // B
    if (rex != 0x40) *p++ = rex;

    // 2) select the right opcode + ModR/M
    if (width == 1) {
        *p++ = 0x80;                // 80 /1 ib : OR r/m8, imm8
        uint8_t modrm = (0<<6)      // mod=00 → memory, no disp
                       | (1<<3)      // reg=1 → OR
                       | (rm & 7);   // r/m = low-3bits of rm
        *p++ = modrm;
        *p++ = (uint8_t)imm;        // imm8
    }
    else if (width == 2) {
        *p++ = 0x66;                // 16-bit prefix
        *p++ = 0x81;                // 81 /1 iw : OR r/m16, imm16
        uint8_t modrm = (0<<6)|(1<<3)|(rm & 7);
        *p++ = modrm;
        *(uint16_t*)p = (uint16_t)imm;  p += 2;
    }
    else if (width == 4) {
        *p++ = 0x81;                // 81 /1 id : OR r/m32, imm32
        uint8_t modrm = (0<<6)|(1<<3)|(rm & 7);
        *p++ = modrm;
        *(uint32_t*)p = (uint32_t)imm;  p += 4;
    }
    else { // width == 8
        *p++ = 0x81;                // 81 /1 id but with REX.W
        uint8_t rexW = 0x48 | ((rm & 8)?1:0);
        *p++ = rexW;
        uint8_t modrm = (0<<6)|(1<<3)|(rm & 7);
        *p++ = modrm;
        *(uint32_t*)p = (uint32_t)imm;  p += 4;
    }

    return p;
}

static uint8_t* emit_and_mem_imm(uint8_t *p,
                                 uint8_t rm,
                                 size_t  width,
                                 uint64_t imm)
{
    /* AND r/m8, imm8      : 80 /4 ib
       AND r/m16/32/64,imm : 81 /4 iw/id  (64b uses imm32 sign-extended)
       AND r/m16/32/64,imm8: 83 /4 ib     (sign-extended) */

    uint8_t rex = 0x40 | ((rm & 8) ? 0x01 : 0);   /* B if rm is r8–r15 */
    if (width == 8) rex |= 0x08;                  /* W for 64-bit */

    if (rex != 0x40) *p++ = rex;

    if (width == 1) {
        *p++ = 0x80;                              /* 80 /4 ib */
        *p++ = (0<<6) | (4<<3) | (rm & 7);        /* mod=00, reg=4, r/m=rm */
        *p++ = (uint8_t)imm;
    } else {
        if (width == 2) *p++ = 0x66;              /* 16-bit operand size */

        /* prefer imm8 form when it fits */
        int64_t simm = (int64_t)imm;
        if (simm >= -128 && simm <= 127) {
            *p++ = 0x83;                          /* 83 /4 ib */
            *p++ = (0<<6) | (4<<3) | (rm & 7);
            *p++ = (uint8_t)imm;
        } else {
            *p++ = 0x81;                          /* 81 /4 iw/id */
            *p++ = (0<<6) | (4<<3) | (rm & 7);
            if (width == 2) {
                *(uint16_t*)p = (uint16_t)imm; p += 2;
            } else {
                *(uint32_t*)p = (uint32_t)imm; p += 4;
            }
        }
    }

    return p;
}


// ------------------------------------------------------------------
static uint8_t* emit_test_reg_imm(uint8_t *p,
                                  uint8_t reg,
                                  size_t  width,
                                  uint64_t imm)
{
    uint8_t rex = 0x40
                | ((width == 64) ? 0x08 : 0)   /* W=1 for 64-bit */
                | ((reg     & 8) ? 0x01 : 0);  /* B=1 for R8–R15 */
    if (rex != 0x40) *p++ = rex;

    if (width == 1) {
        *p++ = 0xF6;                     /* F6 /0 ib → TEST r/m8, imm8 */
        *p++ = 0xC0 | (reg & 7);         /* mod=11, reg=0, r/m=reg */
        *p++ = (uint8_t)imm;
    }
    else {
        if (width == 2) *p++ = 0x66;     /* operand-size override for 16-bit */
        *p++ = 0xF7;                     /* F7 /0 id → TEST r/m(16/32/64), imm32 */
        *p++ = 0xC0 | (reg & 7);         /* mod=11, reg=0, r/m=reg */
        *(uint32_t*)p = (uint32_t)imm;   /* low 32 bits */
        p += 4;
    }
    return p;
}



/**********************************************************************************************************************************************************************************/
static void sigtrap(int sig, siginfo_t *si, void *uctx)
{
    counter++;
    DBG("Sigtrap Counter=%d", counter); 
    (void)sig; (void)si;                       /* si->si_addr is 0 for INT3 */
    ucontext_t *uc = (ucontext_t *)uctx;
    /* address of the INT3 we just hit */
    uint64_t cc_addr = uc->uc_mcontext.gregs[REG_RIP] - 1;   /* 0xCC byte */
    uc->uc_mcontext.gregs[REG_RIP] = cc_addr + 1;   /* skip over INT3 */
    
}

/* ---------------- first SIGSEGV: build trampoline ---------------- */
static void sigsegv(int sig, siginfo_t *si, void *ucv)
{
    counter++;
    ucontext_t *uc = (ucontext_t *)ucv;
    uint64_t    rip   = uc->uc_mcontext.gregs[REG_RIP];
    uint64_t    fault = (uint64_t)si->si_addr;

    int is_load  = 0;
    int is_store = 0;
    int      src_is_imm = 0;
    uint64_t imm64      = 0;

    const cs_x86_op *cmp_rhs = NULL;
    bool   is_cmp_reg_mem = false;
    const cs_x86_op *cmp_lhs = NULL;

    const cs_x86_op *add_src  = NULL;   /* for [mem] ← reg */
    const cs_x86_op *add_dst  = NULL;   /* for   reg ← [mem] */

    

    /* -------- only interested in accesses from the entire secret region -------- */
    if (fault < (uint64_t)secret || fault >= (uint64_t)secret + secret_len) {
        // print the raw fault address, the protected range, and the RIP
        DBG("❌ [BUG] segv outside secret: fault=%p, secret=[%p..%p), rip=%p❌",
            (void*)fault,
            (void*)secret,
            (void*)(secret + PAGE_SZ),
            (void*)rip);

        print_instruction(rip);
        DBG("Disassembling at fault/RIP:");
        dump_code_around(rip, 1, 1);


        // dump a handful of registers
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

        
        // fall through to default so you’ll get a real back-trace
        signal(SIGSEGV, SIG_DFL);
        return;
    }

    DBG("🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺🔺");
    dump("encrypted_secret", (uint8_t*)encrypted_secret, 64);
    // dump("secret_mask_page", (uint8_t*)secret_mask_page, 32);
    DBG("Patching Instruction Number=%d", counter); 
    DBG("secret=%p  enc=%p  DELTA=%lld", secret, encrypted_secret, (long long)SHADOW_DELTA);
    DBG( "✅[INFO] Caught SIGSEGV! Fault address: %p (Inside secret region)✅\n", si->si_addr);
    print_instruction(rip);
    DBG( "Instruction Sequence:\n");
    dump_code(rip, 32);

    /* -------------------- already patched? ------------------------ */
    patch_t *p;
    HASH_FIND(hh, patches, &rip, sizeof(rip), p);
    if (p) abort();                               /* logic bug */

    /* ---------- disassemble *first* instruction ------------------ */
    cs_insn *ins;
    size_t width;
    if (cs_disasm(cs, (uint8_t *)rip, 15, rip, 1, &ins) != 1) abort();
    /* 🚨 scratch register hazard? */
    if (dest_is_scratch_and_src_is_mem(&ins[0])) {
        DBG("⚠️⚠️  slow‑path: %s %s writes to scratch (RDI/R11/R10) ⚠️⚠️"PRIx64,ins[0].mnemonic, ins[0].op_str);
    }
    int clobber = scratch_dest_mask(ins);
    /* === DEBUG DUMP ==================================================== */
    // DBG("Capstone: id=%u  mnemonic=\"%s\"  size=%u",
    //     ins[0].id, ins[0].mnemonic, ins[0].size);

    // const cs_x86 *xd = &ins[0].detail->x86;
    // DBG("prefix bytes = %02x %02x %02x %02x",
    //     xd->prefix[0], xd->prefix[1], xd->prefix[2], xd->prefix[3]);

    // for (int g = 0; g < ins[0].detail->groups_count; g++)
    //     DBG(" group[%d] = %u", g, ins[0].detail->groups[g]);
    /* =================================================================== */

    bool is_rep = has_rep_prefix(ins);
    bool is_movs = (ins->id == X86_INS_MOVSB || ins->id == X86_INS_MOVSW ||
                    ins->id == X86_INS_MOVSD || ins->id == X86_INS_MOVSQ);
    bool is_stos = (ins->id == X86_INS_STOSB || ins->id == X86_INS_STOSW ||
                    ins->id == X86_INS_STOSD || ins->id == X86_INS_STOSQ);

    
    if (is_rep && (is_movs || is_stos)) {
        clobber |= 1;        // bit 0 = skip RDI in save/restore
    }

    const cs_x86   *x   = &ins[0].detail->x86;
    const cs_x86_op*mem = NULL;
    for (int i=0;i<x->op_count;i++)
        if (x->operands[i].type == X86_OP_MEM) { mem=&x->operands[i]; break; }

    if (!mem) ABORT("no MEM operand?");          /* should never happen */

    uint64_t orig_addr = effective_addr(uc, mem, rip);

    /* still interested only if it’s inside the secret page */
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

        case X86_INS_MOVZX:
        case X86_INS_MOVSX:
        case X86_INS_MOVSXD:
            is_load = 1;
            break;

        case X86_INS_ADD:
            {
                if (ins[0].detail->x86.operands[0].type == X86_OP_REG
                && ins[0].detail->x86.operands[1].type == X86_OP_MEM)
                {
                    /* ADD reg, [mem] → fast-path */
                    add_dst = &ins[0].detail->x86.operands[0];
                    is_load = 1;
                }
                else if (ins[0].detail->x86.operands[0].type == X86_OP_MEM
                    && ins[0].detail->x86.operands[1].type == X86_OP_REG)
                {
                    /* the store case, still RMW */
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
        /* --- vector moves --------------------------------------- */
        case X86_INS_MOVAPS:   /* aligned store/load, 128 bit */
        case X86_INS_MOVUPS:   /* unaligned                   */
        case X86_INS_MOVAPD:
        case X86_INS_MOVUPD:
        case X86_INS_VMOVDQA:        /* aligned  mov */
        case X86_INS_VMOVDQU:        /* UNALIGNED mov */
        case X86_INS_MOVDQA:   /* SSE2 aligned 128‑bit        */
        case X86_INS_MOVDQU:   /* SSE2 unaligned 128‑bit      */
        /* optional, Capstone 5+ AVX-512 names: */
        case X86_INS_VMOVDQU32:
        case X86_INS_VMOVDQU64:
            /* vmovdqa ymm0,[mem]  OR  vmovdqa [mem],ymm0          */
            is_load  = (ins[0].detail->x86.operands[1].type == X86_OP_MEM);
            is_store = (ins[0].detail->x86.operands[0].type == X86_OP_MEM);
            break;
        /* ---- REP string-move primitives -------------------------------- */
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
        /* ----------- CMP------------------- */
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

    /* -------------- common metadata we still need ---------------- */
    const cs_x86_op *dst = &ins[0].detail->x86.operands[0];
    int   sign_ext = (ins[0].id == X86_INS_MOVSX || ins[0].id == X86_INS_MOVSXD);

    
    if (is_store) {                           /* store or RMW */
        width     = ins[0].detail->x86.operands[0].size;   /* 1/2/4/8 */
        sign_ext  = 0;                        /* stores never sign-extend */
    } else {                                  /* pure load */
        width = (ins[0].id == X86_INS_MOV)
                  ? dst->size
                  : ins[0].detail->x86.operands[1].size;
    }

    #define STEAL_INIT   2048             /* start with 256 bytes */
    #define TRAMP_GROW   12              /* worst‐case expansion factor */
    
    size_t   steal   = 0;
    size_t   cap     = STEAL_INIT;       /* current capacity of ‘orig’       */
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
    /* 1. steal ≥5 bytes *and* keep extending while the instruction we    */
    /*    just decoded still touches the secret page.                     */
    /* ------------------------------------------------------------------ */
    steal = 0;


    while (1) {
        uintptr_t pc   = rip + steal;
        uintptr_t pend = (pc & ~(pagesize()-1)) + pagesize();   /* 1 byte past page */
        size_t left = pend - pc;
        size_t max  = (left >= 15) ? 15 : left + 15; /* allow x-page insn */

        cs_insn *tmp = NULL;
        size_t n = cs_disasm(cs,(uint8_t*)pc,max,pc,1,&tmp);
        if (n != 1) {
            /* Retry once with full 15 B if we truncated at page edge */
            if (left < 15) {
                max = left + 15;
                n   = cs_disasm(cs,(uint8_t*)pc,max,pc,1,&tmp);
            }
            if (n != 1) ABORT("decode failed");
        }

        if (steal + tmp[0].size > cap) {
            cap *= 2;                                   /* double the buffer   */
            orig = realloc(orig, cap);
            if (!orig) ABORT("oom-realloc");
        }

        /* copy original bytes so we can later re-emit them */
        memcpy(orig + steal, tmp[0].bytes, tmp[0].size);
        steal += tmp[0].size;

        /* decide whether this instruction still points inside the secret */
        int touches_secret = 0;
        int is_mem_store = insn_is_store(tmp);
        const cs_x86 *ix = &tmp[0].detail->x86;
        for (int i = 0; i < ix->op_count; i++) {
            const cs_x86_op *op = &ix->operands[i];
            if (op->type != X86_OP_MEM) continue;

            /* quick test: same base register and same page as the fault */
            uint64_t ea = effective_addr(uc, op, rip + steal - tmp[0].size);
            if (ea >= secret_lo && ea < secret_hi) {
                touches_secret = 1;
                break;
            }
        }

        cs_free(tmp, 1);

        if (steal >= 5 && !touches_secret && !is_mem_store)
            break;            /* we have enough and are past the secret page */
        
    }

    DBG("steal=%zu orig=%02x %02x %02x %02x %02x", steal, orig[0],orig[1],orig[2],orig[3],orig[4]);

    /* -------------------------------------------------------------- */
    /*           2. build trampoline in RWX anon page                 */
    /* -------------------------------------------------------------- */
    size_t   tramp_len = steal * TRAMP_GROW + 64;
    uint8_t *tramp     = alloc_near(rip, tramp_len);
    uint8_t *t = tramp;
    size_t ins_len = ins[0].size;
    int      tail_is_terminal = 0;      /* 0 = falls back, 1 = never returns */
    /* ---- we need to patch the back-jump later if steal grows ---- */
    uint8_t *back_dst_ptr = NULL;   /* points at rel32 or imm64 to fix */
    int      back_is_rel32 = 0;     /* 1 = E9 rel32, 0 = movabs+jmp   */

    int preserve_flags = 0;
    /* special-case: TEST [mem], imm followed by Jcc uses flags directly */
    if (ins[0].id == X86_INS_TEST && is_load && src_is_imm) {
        preserve_flags = 1;
    }

    /*  save caller registers just once */
    t = save_regs(t, clobber, preserve_flags);

    /* -------------------------------------------------------------- */
    /*         (a) translate the faulting instruction itself */
    /* -------------------------------------------------------------- */
    if (is_rep && (is_movs || is_stos)) {
        DBG("is_stos and is_rep");
        size_t unit = (ins[0].id == X86_INS_MOVSB || ins[0].id == X86_INS_STOSB) ? 1 :
                    (ins[0].id == X86_INS_MOVSW || ins[0].id == X86_INS_STOSW) ? 2 :
                    (ins[0].id == X86_INS_MOVSD || ins[0].id == X86_INS_STOSD) ? 4 : 8;

        /* MOVS* reads+writes, STOS* only writes – is_movs is still true/false */
        t = emit_rep_movs_stos(t, is_movs, unit);

    } else if (ins[0].id == X86_INS_CMP && is_load) {
        /* load mem → r11, then cmp r11, rhs */
        cs_x86_op r11op = {
            .type = X86_OP_REG,
                .reg  = X86_REG_R11,
                .size = width   /* or op0->size in the tail path */
            };
        t = emit_lea_r11(t,  mem,           rip);        /* EA → r11       */
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
        t = emit_lea_r11(          t, mem,           rip);
        t = emit_add_r11_imm(      t, SHADOW_DELTA);
        t = emit_load_from_shadow( t, &r11op, width, 0, 0);
        t = emit_xor_with_mask(    t, &r11op, width,
                                   (width==16)?1:(width==32)?2:0);

        /* now emit:   CMP  dst_reg, R11 */
        int     dst_id = rm_id(cmp_lhs);
        uint8_t rex    = 0x40 | 0x01;       /* REX.B=1 for r/m = R11 */
        if (dst_id & 8)    rex |= 0x04;     /* REX.R if dst high reg */
        if (width   == 64) rex |= 0x08;     /* REX.W for 64-bit compares */
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

    /* ───────────────────── slow-path only when dst is scratch ─────────── */
    if (dst_is_scratch) {

        /* 1. save caller-RAX and the *old* dst value */
        t += 0, *t++ = 0x66, *t++ = 0x4C, *t++ = 0x0F, *t++ = 0x6E, *t++ = 0xC8;  /* xmm9 ← rax */
        switch (dst->reg) {
            case X86_REG_R11: case X86_REG_R11D:      /* xmm11 ← r11 */
                *t++=0x66; *t++=0x4D; *t++=0x0F; *t++=0x6E; *t++=0xDB;
                break;
            case X86_REG_R10: case X86_REG_R10D:      /* xmm11 ← r10 */
                *t++=0x66; *t++=0x4D; *t++=0x0F; *t++=0x6E; *t++=0xD2;
                break;
            default:                                  /* xmm11 ← rdi */
                *t++=0x66; *t++=0x4C; *t++=0x0F; *t++=0x6E; *t++=0xDF;
                break;
        }

        /* 2. r11  = shadow address(addr)                               */
        t = emit_lea_r11(t, mem, rip);
        t = emit_add_r11_imm(t, SHADOW_DELTA);

        /* 3.  rdi = r11 (shorter ModRM),  load [rdi] → **EAX**  (NOT r11!) */
        cs_x86_op eaxop = { .type = X86_OP_REG,
                            .reg  = X86_REG_EAX,
                            .size = width };            /* 1/2/4       */
        t = emit_load_from_shadow(t, &eaxop, width, 0, 0);

        /* 4. xor-unmask the freshly loaded value in EAX
            (r11 still holds the address, so the mask test is correct) */
        t = emit_xor_with_mask(t, &eaxop, width, 0);

        /* --- 5. restore the old destination value and do the XOR --- */
        switch (dst->reg) {
            case X86_REG_R11: case X86_REG_R11D:      /* r11 ← xmm11 */
                *t++=0x66; *t++=0x4D; *t++=0x0F; *t++=0x7E; *t++=0xDB;
                *t++=0x41; *t++=0x31; *t++=0xC3;              /* xor r11d,eax */
                break;
            case X86_REG_R10: case X86_REG_R10D:      /* r10 ← xmm11 */
                *t++=0x66; *t++=0x4D; *t++=0x0F; *t++=0x7E; *t++=0xD2;
                *t++=0x41; *t++=0x31; *t++=0xC2;              /* xor r10d,eax */
                break;
            default:                                  /* rdi ← xmm11 */
                *t++=0x66; *t++=0x4C; *t++=0x0F; *t++=0x7E; *t++=0xDF;
                *t++=0x31; *t++=0xC7;                          /* xor edi,eax */
                break;
        }


        /* 6. restore caller-RAX */
        *t++ = 0x66; *t++ = 0x4C; *t++ = 0x0F; *t++ = 0x7E; *t++ = 0xC8;  /* rax ← xmm9 */
    }
    /* ───────────────────── fast-path (no scratch) – unchanged ─────────── */
    else {
        // r11 = shadow address
        t = emit_lea_r11(t, mem, rip);
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

    }
    else if (is_store && src_is_imm && ins[0].id == X86_INS_XOR) {
        /* ---------------- xor [mem], immXX  (read‑modify‑write) ------------- */
        /* r11 = shadow address */
            t = emit_lea_r11(t, mem, rip);
            t = emit_add_r11_imm(t, SHADOW_DELTA);

            /* copy to RDI (low register ⇒ shorter encoding) */
            *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;   /* mov rdi,r11 */

            /* xor  [rdi], imm */
            t = emit_xor_mem_imm(t, 7 /*RDI*/, width, imm64);
    } else if (is_store && src_is_imm && ins[0].id == X86_INS_OR) {
        DBG("OR Store");
        /* ------------ or [mem], immXX (read-modify-write) ----------- */
        /* 1) get shadow address */
        t = emit_lea_r11(t, mem, rip);
        t = emit_add_r11_imm(t, SHADOW_DELTA);

        /* 2) copy to RDI for shorter ModR/M */
        *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;  /* mov rdi,r11 */

        /* 3) OR  [rdi], imm */
        t = emit_or_mem_imm(t, 7 /* RDI */, width, imm64);
    } else if (is_store && src_is_imm && ins[0].id == X86_INS_AND) {
        DBG("AND Store");
        /* ------------ and [mem], immXX (read-modify-write) ----------- */
        /* 1) get shadow address */
        t = emit_lea_r11(t, mem, rip);
        t = emit_add_r11_imm(t, SHADOW_DELTA);

        /* 2) copy to RDI for shorter ModR/M */
        *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;  /* mov rdi,r11 */

        /* 3) AND [rdi], imm */
        t = emit_and_mem_imm(t, 7 /* RDI */, width, imm64);
    } else if (is_load && ins[0].id == X86_INS_OR && ins[0].detail->x86.operands[1].type == X86_OP_MEM) {
        DBG("OR Load");
        // 1) lea r11,mem ; add r11,SHADOW_DELTA
        t = emit_lea_r11(t, mem, rip);
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
        t = emit_lea_r11(t, mem, rip);
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
    } else if (is_load && ins[0].id == X86_INS_ADD && add_dst) {
        DBG("Add Dest");
        /* --- ADD dst_reg, [mem]: load & unmask into R11, then ADD dst,R11 --- */
        cs_x86_op r11op = {
            .type = X86_OP_REG,
            .reg  = X86_REG_R11,
            .size = width
        };
        /* 1) compute shadow address into R11 */
        t = emit_lea_r11(t, mem, rip);
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
            if ((dst_id  & 8) != 0) rex |= 0x01;   /* B=1 if dst high */
            *t++ = rex;

            /* opcode 01 /r = ADD r/m64, r64 */
            *t++ = 0x01;

            /* mod=11, reg=low3(r11), rm=low3(dst) */
            uint8_t modrm = 0xC0
                        | ((r11_id    & 7) << 3)
                        | ( dst_id    & 7);
            *t++ = modrm;
        }
    } else if (is_load && is_store &&
           ins[0].id == X86_INS_ADD &&
           ins[0].detail->x86.operands[0].type == X86_OP_MEM &&
           ins[0].detail->x86.operands[1].type == X86_OP_REG) {
            DBG("RMW ADD([mem], reg)");

            /* RMW: add [mem], reg  ==> redirect the memory operand to shadow */
            const cs_x86_op *mop = &ins[0].detail->x86.operands[0];   // MEM (dst)
            const cs_x86_op *rop = &ins[0].detail->x86.operands[1];   // REG (src)
            int src_id = rm_id(rop);
            if (src_id < 0) ABORT("RMW ADD: bad src reg");

            /* r11 = EA(original) ; if inside secret => r11 += SHADOW_DELTA */
            t = emit_lea_r11(t, mop, rip);
            t = emit_add_r11_imm(t, SHADOW_DELTA);

            /* rdi = r11 (we’ll address [rdi]) */
            *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;   // mov rdi, r11

            /* emit: add [rdi], <src_reg>   (supports width 1/2/4/8) */
            if (width == 2) *t++ = 0x66;

            uint8_t rex = 0x40;
            if (width == 8) rex |= 0x08;        // REX.W
            if (src_id & 8) rex |= 0x04;        // REX.R (src in reg field)
            if (rex != 0x40) *t++ = rex;

            *t++ = (width == 1) ? 0x00 : 0x01;  // ADD r/m8,r8  OR  ADD r/m{16,32,64},r{16,32,64}
            *t++ = (uint8_t)(((src_id & 7) << 3) | 0x07);  // ModRM: mod=00, r/m=RDI(111), reg=src
    } else if (is_load) {
        DBG("Load Instruction");
        /* dst = reg operand 0, width already computed */
        const cs_x86_op *dst_op = &ins[0].detail->x86.operands[0];
        t = emit_lea_r11(t,  mem, rip);
        t = emit_add_r11_imm(t, SHADOW_DELTA);
        t = emit_load_from_shadow(t, dst_op, width, 0, sign_ext);
        t = emit_xor_with_mask(t, dst_op, width, (width==16)?1:(width==32)?2:0);

    } else if (is_store) {
        
        /*Immediate Store => e.g., mov qword ptr [r12], 0 */
        if (src_is_imm) {
                DBG("Immediate Store");
                /* --- RDI = shadow address ------------------------------ */
                t   = emit_lea_r11(t, mem, rip);              /* EA   → r11      */
                t   = emit_add_r11_imm(t, SHADOW_DELTA);      /* +Δ  → r11       */
                *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;        /* mov  rdi,r11    */

                 /* --- R10 = immediate constant -------------------------- */
                *t++ = 0x49; *t++ = 0xBA;                     /* movabs r10,imm64*/
                memcpy(t, &imm64, 8);  t += 8;
                /* mask it if the address is inside the secret page */
                cs_x86_op r10op = { .type = X86_OP_REG,
                                    .reg  = X86_REG_R10D + (width==8?0:0), /* pick R10/R10D */
                                    .size = width };
                t = emit_xor_with_mask(t, &r10op, width, 0);
            

                /* --- store [rdi] ← r11  (width‑specific) --------------- */
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
            /* --- HAZARD: src register aliases our scratch set ------------------- */
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


            t = emit_lea_r11(t,  mem, rip);
            t = emit_add_r11_imm(t, SHADOW_DELTA);
            if (src_is_scratch) {
                    /* 1.  Get plaintext into RAX (top of stack). */
                    *t++ = 0x58;                                 /* pop  rax            */

                    cs_x86_op rax_op = { .type = X86_OP_REG,
                                        .reg  = (width == 1) ? X86_REG_AL  :
                                                (width == 2) ? X86_REG_AX  :
                                                (width == 4) ? X86_REG_EAX :
                                                                X86_REG_RAX,
                                        .size = width };

                    /* 2.  Mask & store. */
                    t = emit_xor_with_mask(t, &rax_op, width,
                                        (width==16)?1:(width==32)?2:0);
                    t = emit_store_to_shadow(t, &rax_op, width, 0);

                    /* 3.  Restore caller’s original RAX. */
                    *t++ = 0x58;                                 /* pop  rax            */
            } else {
                    t = emit_xor_with_mask(t, src_op, width,
                                        (width==16)?1:(width==32)?2:0);
                    t = emit_store_to_shadow(t, src_op, width, 0);
            }

        }
    } else {
        /* RMW-add etc. — adjust if we support other cases */
        ABORT("unhandled first-insn opcode %x", ins[0].id);
    }

    /* ----------------------------------------------------------------------------- */
    /* (b) Save secret address for SIGTRAP, INT3, Save_regs */
    /* ----------------------------------------------------------------------------- */

    // /* (1) move the **accessed address** (original fault addr) into R11 */
    // *t++ = 0x49; *t++ = 0xBB;
    // memcpy(t, &fault, 8);  t += 8;
    // /* (2) INT3 – will raise SIGTRAP -------------------------------- */
    // *t++ = 0xCC;

    /* -------------------------------------------------------------- */
    /*          (b) re-emit each extra stolen instruction safely      */
    /* -------------------------------------------------------------- */
    t = restore_regs(t, clobber, preserve_flags);
    size_t ofs = ins_len;
    
    while (ofs < steal) {
        cs_insn *tmp;
        size_t n = cs_disasm(cs,
                            orig + ofs,        /* bytes to decode         */
                            steal - ofs,
                            rip   + ofs,       /* correct runtime address */
                            1, &tmp);
        if (n != 1) ABORT("tail decode failed");
        // if (dest_is_scratch_and_src_is_mem(&tmp[0])) {
        //     DBG("⚠️⚠️  slow‑path: %s %s writes to scratch (RDI/R11/R10)⚠️⚠️"PRIx64, tmp[0].mnemonic, tmp[0].op_str);
        // }
        // int clobber = scratch_dest_mask(tmp);
        const cs_x86   *tx  = &tmp[0].detail->x86;
        const cs_x86_op *op0 = (tx->op_count > 0 ? &tx->operands[0] : NULL);
        const cs_x86_op*op1 = (tx->op_count > 1 ? &tx->operands[1] : NULL);

        if      (op0 && op0->type == X86_OP_MEM)  width = op0->size;
        else if (op1 && op1->type == X86_OP_MEM)  width = op1->size;

        /* --- decide whether THIS instruction truly touches the secret page --- */
        int touches_secret = 0;
        uint64_t ea           = 0;      /* effective address if we touch */
        for (int i = 0; i < tx->op_count; i++) {
            const cs_x86_op *op = &tx->operands[i];
            if (op->type != X86_OP_MEM) continue;
            ea = effective_addr(uc, op, tmp[0].address);
            if (ea >= secret_lo && ea < secret_hi) {
                touches_secret = 1;
                break;
            }
        }

        if (!touches_secret) {
            /* -------- Case 1: instruction is a direct branch we must fix -------- */
            if (is_direct_branch(tmp)) {
                uint64_t target = tmp[0].detail->x86.operands[0].imm;

                /* Is the target inside the stolen slice? */
                int in_slice = (target >= rip && target < rip + steal);

                if (in_slice) {
                    DBG("Target Is Inside");
                    /* Re-encode the same kind of branch with a fresh displacement */
                    int64_t rel = (int64_t)target - ((int64_t)(t + tmp[0].size));
                    /* We only handle rel32 here; short rel8 will be promoted.     */
                    if (rel >= INT32_MIN && rel <= INT32_MAX) {
                        /* unconditional JMP */
                        if (tmp[0].id == X86_INS_JMP) {
                            *t++ = 0xE9;
                            int32_t r32 = (int32_t)rel;
                            memcpy(t, &r32, 4);  t += 4;
                        }
                        /* CALL rel32 */
                        else if (tmp[0].id == X86_INS_CALL) {
                            *t++ = 0xE8;
                            int32_t r32 = (int32_t)rel;
                            memcpy(t, &r32, 4);  t += 4;
                        }
                        else if (tmp[0].id == X86_INS_LOOP ||      /* LOOP rcx--,  rcx!=0 */
                                tmp[0].id == X86_INS_LOOPNE ||    /* LOOPNZ rcx--, rcx!=0 && ZF==0 */
                                tmp[0].id == X86_INS_LOOPE) {     /* LOOPZ  rcx--, rcx!=0 && ZF==1 */

                            /* --- common prologue: DEC RCX --- */
                            *t++ = 0x48; *t++ = 0xFF; *t++ = 0xC9;            /* dec rcx            */

                            /* save the *old* ZF (before DEC) into r8, then TEST it – restores old ZF */
                            *t++ = 0x9C;                       /* pushfq                          */
                            *t++ = 0x41; *t++ = 0x58;          /* pop  r8                         */
                            *t++ = 0x41; *t++ = 0xF6; *t++ = 0xC0; *t++ = 0x40;  /* test r8b,0x40  */

                            /* abort branch if RCX reached zero */
                            *t++ = 0xE3; *t++ = 0x05;          /* jrcxz  +5 (skip the final Jcc)  */

                            /* ---- choose 32-bit branch encoding ---- */
                            if (tmp[0].id == X86_INS_LOOPE || tmp[0].id == X86_INS_LOOPNE) {
                                /* 0F 84/85 rel32  (JZ / JNZ) */
                                uint8_t opcode = (tmp[0].id == X86_INS_LOOPE) ? 0x84 : 0x85;
                                *t++ = 0x0F; *t++ = opcode;
                                int32_t rel32 = (int32_t)((int64_t)target - ((int64_t)(t + 4)));
                                memcpy(t, &rel32, 4);  t += 4;
                            } else {        /* plain LOOP  -> unconditional JMP rel32 */
                                *t++ = 0xE9;
                                int32_t rel32 = (int32_t)((int64_t)target - ((int64_t)(t + 4)));
                                memcpy(t, &rel32, 4);  t += 4;
                            }
                            }
                        /* conditional branch: use 0F 8* rel32 form                */
                        else {      /* any jcc */
                            uint8_t cc = tmp[0].bytes[0] & 0x0F;   /* keep condition */
                            *t++ = 0x0F; *t++ = 0x80 | cc;         /* long jcc opcodes */
                            int32_t r32 = (int32_t)rel;
                            memcpy(t, &r32, 4);  t += 4;
                        }
                    } else {
                        /* should never happen because slice ≤ 2 GiB, abort safe   */
                        ABORT("rel32 out of range inside slice");
                    }
                } else {
                    DBG("Target Is Outside");

                    int64_t rel = (int64_t)target - ((int64_t)(t + 6));  // 6 = worst-case Jcc imm32
                    int fits_rel32 = (rel >= INT32_MIN && rel <= INT32_MAX);

                    /* --------------- CALL ----------------------------------- */
                    if (tmp[0].id == X86_INS_CALL)
                    {
                        /* movabs r11,target ; call r11 */
                        *t++ = 0x49; *t++ = 0xBB;                   /* movabs r11, imm64   */
                        memcpy(t, &target, 8);  t += 8;
                        *t++ = 0x41; *t++ = 0xFF; *t++ = 0xD3;      /* call   r11          */
                    }

                    /* --------------- unconditional JMP ---------------------- */
                    else if (tmp[0].id == X86_INS_JMP)
                    {
                        uint8_t *disp_site;
                        *t++ = 0xFF; *t++ = 0x25;                   /* jmp [rip+0]         */
                        disp_site = t;  t += 4;
                        memcpy(t, &target, 8);  t += 8;
                        int32_t disp32 = 0;                         /* literal follows     */
                        memcpy(disp_site, &disp32, 4);
                    }

                    /* --------------- conditional Jcc ------------------------ */
                    else if (   tmp[0].id == X86_INS_JA   || tmp[0].id == X86_INS_JAE
                        || tmp[0].id == X86_INS_JB   || tmp[0].id == X86_INS_JBE
                        || tmp[0].id == X86_INS_JE   || tmp[0].id == X86_INS_JNE
                        || tmp[0].id == X86_INS_JG   || tmp[0].id == X86_INS_JGE
                        || tmp[0].id == X86_INS_JL   || tmp[0].id == X86_INS_JLE
                        || tmp[0].id == X86_INS_JO   || tmp[0].id == X86_INS_JNO
                        || tmp[0].id == X86_INS_JP   || tmp[0].id == X86_INS_JNP
                        || tmp[0].id == X86_INS_JS   || tmp[0].id == X86_INS_JNS)
                    {
                        DBG("conditional jcc");
                            uint8_t cc;
                            if (tmp[0].bytes[0] == 0x0F) {
                                // long form: 0x0F 0x8? → condition is low nibble of bytes[1]
                                cc = tmp[0].bytes[1] & 0x0F;
                            }
                            else {
                                // short form: 0x7? → condition is low nibble of bytes[0]
                                cc = tmp[0].bytes[0] & 0x0F;
                            }

                        if (fits_rel32) {
                            /* 0F 8cc rel32  (long form) */
                            *t++ = 0x0F; *t++ = 0x80 | cc;
                            int32_t r32 = (int32_t)rel;
                            memcpy(t, &r32, 4);  t += 4;
                        } else {
                            /* --- veneer: Jcc-inverted short-jump over absolute JMP -------- */
                            uint8_t inv = cc ^ 1;                   /* invert condition     */
                            *t++ = 0x70 | inv; *t++ = 0x0E;         /* Jcc-inv +14 bytes    */

                            /* jmp qword ptr [rip+0] */
                            *t++ = 0xFF; *t++ = 0x25;
                            uint8_t *disp_site = t;  t += 4;
                            memcpy(t, &target, 8);  t += 8;
                            int32_t zero = 0;
                            memcpy(disp_site, &zero, 4);
                        }
                    }

                    /* --------------- LOOP / LOOPE / LOOPNE ------------------ */
                    else if (tmp[0].id == X86_INS_LOOP   ||
                            tmp[0].id == X86_INS_LOOPE  ||
                            tmp[0].id == X86_INS_LOOPNE)
                    {
                        /* DEC RCX sets ZF/CF the same way real LOOP would */
                        *t++ = 0x48; *t++ = 0xFF; *t++ = 0xC9;      /* dec rcx             */

                        /* Inverted-condition veneer (RCX!=0 && {ZF test}) */

                        /* (1) RCX==0  → fall-through */
                        *t++ = 0xE3; *t++ = 0x0F;                   /* jrcxz +15           */

                        /* (2) optional ZF test for LOOPE / LOOPNE */
                        if (tmp[0].id != X86_INS_LOOP) {
                            /* pushfq / pop r8 / test r8b,0x40  (preserves flags) */
                            *t++ = 0x9C;
                            *t++ = 0x41; *t++ = 0x58;
                            *t++ = 0x41; *t++ = 0xF6; *t++ = 0xC0; *t++ = 0x40;
                            /* if ZF mismatches -> jump over JMP abs64 */
                            uint8_t cond = (tmp[0].id == X86_INS_LOOPE) ? 0x75 : 0x74; /* jne / je */
                            *t++ = cond; *t++ = 0x07;                /* Jcc +7          */
                        }

                        /* (3) absolute JMP to target */
                        *t++ = 0xFF; *t++ = 0x25;
                        uint8_t *disp_site = t;  t += 4;
                        memcpy(t, &target, 8);  t += 8;
                        int32_t zero = 0;
                        memcpy(disp_site, &zero, 4);
                    }

                    /* --------------- JCXZ / JRCXZ --------------------------- */
                    else if (tmp[0].id == X86_INS_JRCXZ || tmp[0].id == X86_INS_JCXZ)
                    {
                        /* same veneer style – invert condition */
                        *t++ = 0xE3; *t++ = 0x0E;                   /* jrcxz +14          */

                        *t++ = 0xFF; *t++ = 0x25;
                        uint8_t *disp_site = t;  t += 4;
                        memcpy(t, &target, 8);  t += 8;
                        int32_t zero = 0;
                        memcpy(disp_site, &zero, 4);
                    }

                    /* --------------- unknown direct branch ------------------ */
                    else
                    {
                        ABORT("unhandled direct branch with external target");
                    }
                }
                    // tail_is_terminal = 1;          /* skip common epilogue */
                    
                    cs_free(tmp, 1);
                    break;
                /* done handling direct branch */
            }
            /* -------- Case 2:  any *indirect* control-flow op (RET, jmp rax, call r/m) ---- */
            else if (tmp[0].id == X86_INS_LEAVE    ||
                tmp[0].id == X86_INS_RET      ||
                tmp[0].id == X86_INS_RETF     ||
                tmp[0].id == X86_INS_JMP      && tmp[0].detail->x86.operands[0].type != X86_OP_IMM ||
                tmp[0].id == X86_INS_CALL     && tmp[0].detail->x86.operands[0].type != X86_OP_IMM)
            {
                DBG("Target Is indirect");

                /* now re-emit the RET / indirect JMP / indirect CALL literally
                (no harm – it will execute *once* and really leave the function) */
                memcpy(t, tmp[0].bytes, tmp[0].size);
                t += tmp[0].size;

                /* consume the *next* instruction if it is `ret` */
                if (ofs + tmp[0].size < steal &&
                    orig[ofs + tmp[0].size] == 0xC3) {  /* 0xC3 = RET */
                    *t++ = 0xC3;
                    ofs += 1;       /* skip it in the outer loop */
                }

                /* we’re done – everything after the RET is dead code, so stop stealing */
                tail_is_terminal = 1;          /* skip epilogue, RET ends it */
                
                cs_free(tmp,1);
                break;
            }
            else if (tmp[0].id == X86_INS_LEA) {
                DBG("LEA not touching secret");
            // --- extract operands ----------------------------------
                const cs_x86 *x = &tmp[0].detail->x86;
                const cs_x86_op *mop = NULL, *dop = NULL;
                for (int i = 0; i < x->op_count; i++) {
                    if (x->operands[i].type == X86_OP_MEM)  mop = &x->operands[i];
                    if (x->operands[i].type == X86_OP_REG)  dop = &x->operands[i];
                }
                if (!mop || !dop) ABORT("tail-copy LEA: missing operands");

                // If LEA is NOT RIP-relative, do not rewrite it; copy the original bytes.
                if (mop->mem.base != X86_REG_RIP) {
                    memcpy(t, (void *)tmp[0].address, tmp[0].size);
                    t += tmp[0].size;
                } else {
                    // RIP-relative LEA must be relocated: re-emit with SAME dest width,
                    // and a new disp relative to the trampoline RIP.
                    int dst_id = rm_id(dop);
                    bool dst_is_64 = (dop->size == 8);      // e.g., rax -> 8, eax -> 4

                    // REX: only when needed; never force W=1 for 32-bit dest.
                    uint8_t rex = 0x40;
                    if (dst_is_64)      rex |= 0x08;        // REX.W
                    if (dst_id & 8)     rex |= 0x04;        // REX.R
                    if (rex != 0x40)   *t++ = rex;

                    *t++ = 0x8D;                            // LEA r, m
                    *t++ = (0 << 6) | ((dst_id & 7) << 3) | 5; // mod=00, rm=101 (RIP)

                    uint64_t target = effective_addr(uc, mop, tmp[0].address);
                    int32_t disp = (int32_t)(target - ((uint64_t)t + 4));
                    memcpy(t, &disp, 4);
                    t += 4;
                }
            }            
            /* -------- Case 3: anything else – safe to copy verbatim ---------- */
            else {
                DBG("copy verbatim");
                memcpy(t, tmp[0].bytes, tmp[0].size);
                t += tmp[0].size;
            }
        } 
        else {
            /* Stolen Instruction Touches Secret Ladder*/
            const cs_x86_op *mop = (op0 && op0->type == X86_OP_MEM) ? op0 : (op1 && op1->type == X86_OP_MEM) ? op1 : NULL;
            if (!mop)  ABORT("logic bug: expected mem operand");
            // touches secret → doing the shadow load/store
            if (dest_is_scratch_and_src_is_mem(&tmp[0])) {
                DBG("⚠️⚠️  slow‑path: %s %s writes to scratch (RDI/R11/R10) ⚠️⚠️"PRIx64,ins[0].mnemonic, ins[0].op_str);
            }
            int clobber = scratch_dest_mask(tmp);
            t = save_regs(t, clobber, 0);
            if (tmp[0].id == X86_INS_ADD &&
                op0->type == X86_OP_MEM &&
                op1 && op1->type == X86_OP_REG) {
                t = emit_lea_r11(t, mop, tmp[0].address);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_xor_with_mask(t, op1, width,(width==16)?1:(width==32)?2:0);
                t = emit_store_to_shadow(t, op1, op0->size, 0);
            }
            else if (tmp[0].id == X86_INS_MOV &&
                     op0->type == X86_OP_MEM &&
                     op1 && op1->type == X86_OP_REG) {
                DBG("store register");
                t = emit_lea_r11(t, mop, tmp[0].address);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_xor_with_mask(t, op1, width,(width==16)?1:(width==32)?2:0);
                t = emit_store_to_shadow(t, op1, op0->size, 0);
            }
            else if (tmp[0].id == X86_INS_MOV &&
                     op0->type == X86_OP_REG &&
                     op1 && op1->type == X86_OP_MEM) {
                t = emit_lea_r11(t, mop, tmp[0].address);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_load_from_shadow(t, op0, op1->size, 0, 0);
                t = emit_xor_with_mask(t, op0, width, (width==16)?1:(width==32)?2:0);
            }
            else if ((tmp[0].id == X86_INS_VMOVDQA ||
                      tmp[0].id == X86_INS_VMOVDQU) &&
                     op0->type == X86_OP_MEM &&
                     op1 && op1->type == X86_OP_REG) {
                t = emit_lea_r11(t, mop, tmp[0].address);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_xor_with_mask(t, op1, width,(width==16)?1:(width==32)?2:0);
                t = emit_store_to_shadow(t, op1, op0->size, 0);
            }
            else if ((tmp[0].id == X86_INS_VMOVDQA ||
                      tmp[0].id == X86_INS_VMOVDQU) &&
                     op0->type == X86_OP_REG &&
                     op1 && op1->type == X86_OP_MEM) {
                t = emit_lea_r11(t, mop, tmp[0].address);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_load_from_shadow(t, op0, op1->size, 0, 0);
                t = emit_xor_with_mask(t, op0, width, (width==16)?1:(width==32)?2:0);
            }
            else if ((tmp[0].id == X86_INS_MOVAPS  || tmp[0].id == X86_INS_MOVUPS ||
                     tmp[0].id == X86_INS_MOVAPD  || tmp[0].id == X86_INS_MOVUPD ||
                     tmp[0].id == X86_INS_MOVDQA  || tmp[0].id == X86_INS_MOVDQU) &&
                     op0->type == X86_OP_MEM &&
                     op1 && op1->type == X86_OP_REG) {
                t = emit_lea_r11(t, mop, tmp[0].address);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_xor_with_mask(t, op1, width,(width==16)?1:(width==32)?2:0);
                t = emit_store_to_shadow(t, op1, op0->size, 0);
            }
            else if ((tmp[0].id == X86_INS_MOVAPS  || tmp[0].id == X86_INS_MOVUPS ||
                     tmp[0].id == X86_INS_MOVAPD  || tmp[0].id == X86_INS_MOVUPD ||
                     tmp[0].id == X86_INS_MOVDQA  || tmp[0].id == X86_INS_MOVDQU) &&
                     op0->type == X86_OP_REG &&
                     op1 && op1->type == X86_OP_MEM) {
                t = emit_lea_r11(t, mop, tmp[0].address);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_load_from_shadow(t, op0, op1->size, 0, 0);
                t = emit_xor_with_mask(t, op0, width, (width==16)?1:(width==32)?2:0);
            }
            /* -------- mov [mem], immXX  (store immediate) -------- */
            else if (tmp[0].id == X86_INS_MOV &&
                     op0->type == X86_OP_MEM &&
                     op1 && op1->type == X86_OP_IMM) {
                DBG("store immediate touching secret");
                uint64_t imm64 = (uint64_t)op1->imm;  /* capture constant */
                size_t   w     = op0->size;           /* 1 / 2 / 4 / 8    */

                #if PDM_MASKING
                /* Mask only the bytes that will actually be stored */
                if (w == 8) {
                    imm64 ^= (uint64_t)PDM_MASK64;
                } else if (w == 4) {
                    imm64 = (imm64 & ~0xFFFFFFFFULL) | (((uint32_t)imm64 ^ (uint32_t)PDM_MASK32) & 0xFFFFFFFFU);
                } else if (w == 2) {
                    imm64 = (imm64 & ~0xFFFFULL) | (((uint16_t)imm64 ^ (uint16_t)PDM_MASK16) & 0xFFFFU);
                } else if (w == 1) {
                    imm64 = (imm64 & ~0xFFULL) | (((uint8_t)imm64 ^ (uint8_t)PDM_MASK_BYTE) & 0xFFU);
                } else {
                    ABORT("imm-store tail: bad width %zu", w);
                }
                #endif


                /* --- RDI = shadow address ----------------------------- */
                t   = emit_lea_r11(t, mop, tmp[0].address); /* EA → r11        */
                t   = emit_add_r11_imm(t, SHADOW_DELTA);    /* +Δ → r11        */
                *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;      /* mov rdi,r11     */

                /* --- R11 = immediate constant ------------------------- */
                *t++ = 0x49; *t++ = 0xBB;                    /* movabs r11,imm64 */
                memcpy(t, &imm64, 8);  t += 8;

                /* --- store [rdi] ← r11  (width-specific) -------------- */
                if (w == 8) {
                    *t++ = 0x4C; *t++ = 0x89; *t++ = 0x1F;                 /* mov [rdi], r11 */
                } else if (w == 4) {
                    *t++ = 0x44; *t++ = 0x89; *t++ = 0x1F;                 /* mov [rdi], r11d */
                } else if (w == 2) {
                    *t++ = 0x66; *t++ = 0x44; *t++ = 0x89; *t++ = 0x1F;    /* mov [rdi], r11w */
                } else if (w == 1) {
                    *t++ = 0x44; *t++ = 0x88; *t++ = 0x1F;                 /* mov [rdi], r11b */
                } else {
                    ABORT("imm-store tail: bad width %zu", w);
                }
            }
            /* -------- cmp mem, imm/reg -------------------------------- */
            else if (tmp[0].id == X86_INS_CMP &&
                     op0->type == X86_OP_MEM) {
                /* load → r11 */
                cs_x86_op r11op = { .type = X86_OP_REG, .reg = X86_REG_R11, .size = op0->size };
                t = emit_lea_r11(t, mop, tmp[0].address);
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
            /* -------- cmp  reg, [mem]  (opcode 0x3B) ----------------------------- */
            else if (tmp[0].id == X86_INS_CMP &&
                    op0->type == X86_OP_REG) 
            {
                DBG("cmp  reg, [mem]");
                /* --- 1) r11 = shadow address ------------------------------------ */
                t = emit_lea_r11(t, op1, tmp[0].address);   /* r11 = &secret            */
                t = emit_add_r11_imm(t, SHADOW_DELTA);      /* into shadow copy         */

                /* --- 2) load and un-XOR the secret ------------------------------ */
                cs_x86_op r11op = { .type  = X86_OP_REG,
                                    .reg   = X86_REG_R11,
                                    .size  = op1->size };

                int width = op1->size * 8;                  /* 16 / 32 / 64             */

                t = emit_load_from_shadow(t, &r11op, op1->size, 0, 0);
                t = emit_xor_with_mask   (t, &r11op, width,
                                            (width==16)?1 : (width==32)?2 : 0);

                /* --- 3)   cmp  dst, r11   (opcode 0x3B /r with mod = 11) -------- */
                int dst_id  = rm_id(op0);                   /* register being compared  */

                uint8_t rex = 0x40;                         /* REX base                */
                if (width == 64)   rex |= 0x08;             /* REX.W                   */
                if (dst_id & 8)    rex |= 0x04;             /* REX.R                   */
                rex              |= 0x01;                   /* REX.B (r/m = r11)       */
                *t++ = rex;

                *t++ = 0x3B;                                /* cmp r32/64, r/m32/64    */

                uint8_t modrm = ((dst_id & 7) << 3) | 0x03; /* mod = 11, r/m = r11     */
                *t++ = modrm;
            }

            /* -------- XOR  reg, [mem]  (dst ^= *(addr)) ------------------ */
            else if (tmp[0].id == X86_INS_XOR &&
                    op0->type == X86_OP_REG &&                /* dst is register     */
                    op1 && op1->type == X86_OP_MEM) {         /* src is memory       */

                DBG("XOR reg, [mem] touching secret");

                /* r11 := shadow-address(addr) */
                t  = emit_lea_r11(t, mop, tmp[0].address);
                t  = emit_add_r11_imm(t, SHADOW_DELTA);

                /* r11 := plaintext value = load(addr)^mask */
                cs_x86_op r11op = {
                    .type = X86_OP_REG,
                    .reg  = X86_REG_R11,
                    .size = op0->size
                };
                t = emit_load_from_shadow(t, &r11op, r11op.size, 0, 0);
                t = emit_xor_with_mask  (t, &r11op, r11op.size, 0);

                /* dst ^= r11   (opcode 31h, r/m = dst, reg = r11) */
                uint8_t dst_id = rm_id(op0);
                uint8_t rex    = 0x40;                 /* base REX                 */
                if (r11op.size == 8)  rex |= 0x08;     /* W bit for 64-bit         */
                if (dst_id & 8)       rex |= 0x01;     /* B selects high dst reg   */
                rex                  |= 0x04;          /* R selects r11            */
                if (rex != 0x40)      *t++ = rex;

                if (r11op.size == 2)  *t++ = 0x66;     /* 16-bit override          */

                *t++ = 0x31;                           /* XOR r/m, reg             */
                *t++ = 0xC0 | (3 << 3) | (dst_id & 7);/* mod=11 reg=r11 rm=dst    */
            }

            /* -------- XOR  [mem], reg  (RMW) ----------------------------- */
            else if (tmp[0].id == X86_INS_XOR &&
                     op0->type == X86_OP_MEM &&
                     op1 && op1->type == X86_OP_REG) {
                DBG("XOR touching secret XOR  [mem], reg  (RMW)");

                /* 1) r11 = shadow address */
                t = emit_lea_r11(t, mop, tmp[0].address);   /* EA  → r11        */
                t = emit_add_r11_imm(t, SHADOW_DELTA);      /* +Δ  → r11        */

                /* 2) put the address in rdi (gives the shortest ModRM) */
                *t++ = 0x4C; *t++ = 0x89; *t++ = 0xDF;      /* mov rdi,r11      */

                /* 3) emit   xor  [rdi], src_reg   (width 1/2/4/8) */
                uint8_t src_id = rm_id(op1);
                size_t   w     = op0->size;                 /* operand width    */

                uint8_t rex = 0x40;                         /* 0100 WRXB        */
                if (w == 8)   rex |= 0x08;                  /* W=1 for 64‑bit   */
                if (src_id & 8) rex |= 0x04;               /* R = src high bit */
                /* B stays 0 (rdi is id=7, no high bit)      */
                if (rex != 0x40) *t++ = rex;

                if (w == 2)      *t++ = 0x66;               /* 16‑bit override  */

                *t++ = (w == 1) ? 0x30 : 0x31;              /* XOR r/m8 vs r/m16/32/64 */

                /* ModRM: mod=00 (mem), reg=src_id&7, rm=7 (rdi) */
                *t++ = (uint8_t)(((src_id & 7) << 3) | 0x07);
            }

            /* -------- LEA touching secret: compute→translate→write dest ----- */
            else if (tmp[0].id == X86_INS_LEA) {
                DBG("LEA Touching Secret — translate EA into shadow");

                /* extract operands */
                const cs_x86 *x = &tmp[0].detail->x86;
                const cs_x86_op *mop = NULL, *dop = NULL;
                for (int i = 0; i < x->op_count; i++) {
                    if (x->operands[i].type == X86_OP_MEM) mop = &x->operands[i];
                    if (x->operands[i].type == X86_OP_REG) dop = &x->operands[i];
                }
                if (!mop || !dop) ABORT("LEA touching secret: missing operands");

                /* r11 := EA (rebuild original ModRM/SIB/disp), based at the original RIP */
                t = emit_lea_r11(t, mop, tmp[0].address);

                /* if EA ∈ [secret, secret+len), add SHADOW_DELTA */
                t = emit_add_r11_imm(t, SHADOW_DELTA);

                /* move translated address into the LEA destination (16/32/64) */
                t = emit_mov_dst_from_r11(t, dop);
            }

            /* -------- MOVZX / MOVSX  reg, [mem] -------------------------- */
            else if ((tmp[0].id == X86_INS_MOVZX || tmp[0].id == X86_INS_MOVSX) &&
                     op0->type == X86_OP_REG &&
                     op1 && op1->type == X86_OP_MEM) {
                int sign = (tmp[0].id == X86_INS_MOVSX);
                t = emit_lea_r11(t, mop, tmp[0].address);
                t = emit_add_r11_imm(t, SHADOW_DELTA);
                t = emit_load_from_shadow(t,               /* dst ← shadow */
                                          op0,             /* destination reg  */
                                          op1->size,       /* width = 1 or 2   */
                                          0,
                                          sign);           /* sign / zero ext  */
                t = emit_xor_with_mask(t, op0, width, (width==16)?1:(width==32)?2:0);
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
            t = restore_regs(t, clobber, 0);
        }

        DBG(" tail[%2zu] at 0x%" PRIx64 ": %s %s  → touches_secret=%d",ofs, tmp[0].address, tmp[0].mnemonic, tmp[0].op_str, touches_secret);
        ofs += tmp[0].size;
        cs_free(tmp, 1);
    }


    /* ----------------------------------------------------------------------------- */
    /* (c) Construct the end of trampoline, If we are not leaving the trampoline. */
    /* ----------------------------------------------------------------------------- */
    if (!tail_is_terminal) {
        /* (3) jump back right after the stolen chunk ------------------- */
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
            /* Plan B : 14-byte  movabs r11,imm64 ; jmp r11 */
            *t++ = 0x49; *t++ = 0xBB;          /* movabs r11, imm64 */
            back_dst_ptr = t;                 /* <-- remember imm64 */
            back_is_rel32 = 0;
            uint64_t imm_tmp = rip + steal;   /* provisional          */
            memcpy(t, &imm_tmp, 8);  t += 8;
            *t++ = 0x41; *t++ = 0xFF; *t++ = 0xE3;   /* jmp r11        */
        }
    }
    

    DBG("🏃  tramp @%p  size=%zu", tramp, (size_t)(t - tramp));
    DBG("tramp @%p →", tramp);
    #ifdef DEBUG
    {
        /* print the same pid/tid prefix as DBG does, but stay on one line */
        fprintf(stderr, "[%d:%d]   ", (int)getpid(), (int)TID);

        for (size_t i = 0; i < (size_t)(t - tramp); i++)
            fprintf(stderr, "%02x ", tramp[i]);

        fprintf(stderr, "\n");            /* single terminating newline */
        fprintf(stderr, "Trampoline Instructions");
        fprintf(stderr, "\n");
        dump_bytes_as_code(tramp, (size_t)(t - tramp), (uint64_t)tramp);
    }
    #endif


    /* ---------- 3. patch original site with a jump to tramp --------- */
    int64_t rel = (int64_t)tramp - (int64_t)(rip + 5);
    DBG("[patch] rip=%p tramp=%p  rel=%lld (0x%llx)",
       (void*)rip, (void*)tramp,
       (long long)rel, (unsigned long long)rel);
    void   *page        = (void *)(rip & ~(pagesize() - 1));
    size_t  need_bytes  =   /* 5-byte E9 rel32  or 14-byte absolute */
            ((rel >= INT32_MIN && rel <= INT32_MAX) ? 5 : 14);
    /* --- ensure we won’t overwrite partial instructions ----------------- */
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
        DBG("[patch] Plan B (14-byte abs-jmp) – rel outside int32");
        /* ---------------- Plan B : 14-byte absolute jump ------------ */
        /* layout: 49 BB imm64         mov r11, imm64
                41 FF E3            jmp r11          */
        uint8_t jmp14[13] = { 0x49, 0xBB };
        memcpy(jmp14 + 2, &tramp, 8);               /* imm64 */
        jmp14[10] = 0x41; jmp14[11] = 0xFF; jmp14[12] = 0xE3;

        /* ensure we have at least 14 bytes; steal more if necessary */
        while (steal < 14) {
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

        memmove((void *)rip, jmp14, 13);             /* write patch */

        if (steal > 13)
            memset((uint8_t *)rip + 14, 0x90, steal - 14);
    }

    #ifdef DEBUG
    {
        fprintf(stderr, "\nPatched Instructions\n");
        // dump_code_around(rip, 2,2);
        dump_code(rip, 32);
    }
    #endif

    /* ------------------------------------------------------------------ */
    /*  Final‑fix the return jump, now that `steal` is definitive      */
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
    /*           4. remember patch                                    */
    /* -------------------------------------------------------------- */
    p          = malloc(sizeof(*p));
    p->rip     = rip;
    p->orig_len= steal;
    p->tramp   = tramp;
    HASH_ADD(hh, patches, rip, sizeof(rip), p);

    cs_free(ins, 1);
    /* return → re-execute -> JMP tramp  */
}

/**********************************************************************************************************************************************************************************/
/* ---------------- alternate signal stack ---------------- */
static uint8_t *alt_stack_mem = NULL;
/* ---------------- constructor --------------------------- */
__attribute__((constructor))
static void init(void)
{
    /* 1. Set up Capstone */
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK)
        die("cs_open");
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    /* 1. allocate a *dedicated* RW buffer for the alt-stack */
    alt_stack_mem = mmap(NULL, ALT_STACK_SZ,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (alt_stack_mem == MAP_FAILED) die("mmap alt_stack");
    
    /* 2. Install an alternate signal stack */
    {
        stack_t ss = {
            .ss_sp    = alt_stack_mem,
            .ss_size  = ALT_STACK_SZ,
            .ss_flags = 0
        };
        if (sigaltstack(&ss, NULL) == -1)
            die("sigaltstack");
    }

    /* 3. Common sa_flags for both handlers */
    struct sigaction sa={0};
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    // sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sa.sa_sigaction = sigsegv;
    sigaction(SIGSEGV, &sa, NULL);

    // sa.sa_sigaction = sigtrap;
    // sigaction(SIGTRAP, &sa, NULL);

    DBG("[Signal-2] shadow-trampoline ready\n");
}