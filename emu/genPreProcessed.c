# 1 "/Users/bbarrows/repos/ish/jit/gen.c"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 363 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "/Users/bbarrows/repos/ish/jit/gen.c" 2
# 1 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 1 3 4
# 42 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 3 4
#pragma clang module import Darwin.cdefs /* clang -E: implicit import for #include <sys/cdefs.h> */
# 76 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 3 4
void __assert_rtn(const char *, const char *, int, const char *) __attribute__((__noreturn__)) __attribute__((__cold__)) __attribute__((__disable_tail_calls__));
# 2 "/Users/bbarrows/repos/ish/jit/gen.c" 2
# 1 "/Users/bbarrows/repos/ish/jit/gen.h" 1

# 1 "/Users/bbarrows/repos/ish/jit/jit.h" 1

# 1 "/Users/bbarrows/repos/ish/misc.h" 1

# 1 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 1 3 4
# 42 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 3 4
#pragma clang module import Darwin.cdefs /* clang -E: implicit import for #include <sys/cdefs.h> */
# 76 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 3 4
void __assert_rtn(const char *, const char *, int, const char *) __attribute__((__noreturn__)) __attribute__((__cold__)) __attribute__((__disable_tail_calls__));
# 5 "/Users/bbarrows/repos/ish/misc.h" 2
#pragma clang module import Darwin.C.stdio /* clang -E: implicit import for #include <stdio.h> */
#pragma clang module import Darwin.C.stdlib /* clang -E: implicit import for #include <stdlib.h> */
#pragma clang module import Darwin.C.stdint /* clang -E: implicit import for #include <stdint.h> */
#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */
# 1 "/Applications/Xcode11.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/11.0.0/include/stdnoreturn.h" 1 3 4
# 10 "/Users/bbarrows/repos/ish/misc.h" 2
#pragma clang module import Darwin.POSIX.sys.types /* clang -E: implicit import for #include <sys/types.h> */
# 40 "/Users/bbarrows/repos/ish/misc.h"
static inline void __use(int dummy __attribute__((unused)), ...)
{
}

# 58 "/Users/bbarrows/repos/ish/misc.h"
typedef int64_t    sqword_t;
typedef uint64_t   qword_t;
typedef uint32_t   dword_t;
typedef int32_t    sdword_t;
typedef uint16_t   word_t;
typedef uint8_t    byte_t;

typedef dword_t    addr_t;
typedef dword_t    uint_t;
typedef sdword_t   int_t;

typedef sdword_t   pid_t_;
typedef dword_t    uid_t_;
typedef word_t     mode_t_;
typedef sqword_t   off_t_;
typedef dword_t    time_t_;
typedef dword_t    clock_t_;
# 4 "/Users/bbarrows/repos/ish/jit/jit.h" 2
# 1 "/Users/bbarrows/repos/ish/emu/memory.h" 1

#pragma clang module import Darwin.C.stdatomic /* clang -E: implicit import for #include <stdatomic.h> */
#pragma clang module import Darwin.POSIX.unistd /* clang -E: implicit import for #include <unistd.h> */
# 1 "/Users/bbarrows/repos/ish/util/list.h" 1

#pragma clang module import Darwin.POSIX.unistd /* clang -E: implicit import for #include <unistd.h> */
#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */
#pragma clang module import Darwin.C.stddef /* clang -E: implicit import for #include <stddef.h> */

struct list {
    struct list *next, *prev;
};

static inline void list_init(struct list *list)
{
    list->next = list;
    list->prev = list;
}

static inline _Bool list_null(struct list *list)
{
    return list->next == ((void *)0) && list->prev == ((void *)0);
}

static inline _Bool list_empty(struct list *list)
{
    return list->next == list || list_null(list);
}

static inline void _list_add_between(struct list *prev, struct list *next, struct list *item)
{
    prev->next = item;
    item->prev = prev;
    item->next = next;
    next->prev = item;
}

static inline void list_add_tail(struct list *list, struct list *item)
{
    _list_add_between(list->prev, list, item);
}

static inline void list_add(struct list *list, struct list *item)
{
    _list_add_between(list, list->next, item);
}

static inline void list_add_before(struct list *before, struct list *item)
{
    list_add_tail(before, item);
}

static inline void list_add_after(struct list *after, struct list *item)
{
    list_add(after, item);
}

static inline void list_init_add(struct list *list, struct list *item)
{
    if (list_null(list)) list_init(list);
    list_add(list, item);
}

static inline void list_remove(struct list *item)
{
    item->prev->next = item->next;
    item->next->prev = item->prev;
    item->next = item->prev = ((void *)0);
}

static inline void list_remove_safe(struct list *item)
{
    if (!list_null(item)) list_remove(item);
}

# 89 "/Users/bbarrows/repos/ish/util/list.h"
static inline unsigned long list_size(struct list *list)
{
    unsigned long count = 0;
    struct list *item;
    for (item = (list)->next; item != (list); item = item->next) {
        count++;
    }
    return count;
}

# 7 "/Users/bbarrows/repos/ish/emu/memory.h" 2
# 1 "/Users/bbarrows/repos/ish/util/sync.h" 1

#pragma clang module import Darwin.C.stdatomic /* clang -E: implicit import for #include <stdatomic.h> */
#pragma clang module import Darwin.POSIX.pthread.pthread /* clang -E: implicit import for #include <pthread.h> */
#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */
#pragma clang module import Darwin.C.setjmp /* clang -E: implicit import for #include <setjmp.h> */

typedef struct {
    pthread_mutex_t m;
    pthread_t owner;
} lock_t;

static inline void __lock(lock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line)
{
    pthread_mutex_lock(&lock->m);
    lock->owner = pthread_self();
}

static inline void unlock(lock_t *lock)
{
    pthread_mutex_unlock(&lock->m);
}

typedef struct {
    pthread_cond_t cond;
} cond_t;

void cond_init(cond_t *cond);

void cond_destroy(cond_t *cond);

int wait_for(cond_t *cond, lock_t *lock, struct timespec *timeout);

int wait_for_ignore_signals(cond_t *cond, lock_t *lock, struct timespec *timeout);

void notify(cond_t *cond);

void notify_once(cond_t *cond);

typedef pthread_rwlock_t wrlock_t;
static inline void wrlock_init(wrlock_t *lock)
{
    pthread_rwlockattr_t *pattr = ((void *)0);

    pthread_rwlock_init(lock, pattr);
}

extern __thread sigjmp_buf unwind_buf;
extern __thread _Bool should_unwind;
static inline int sigunwind_start()
{
    if (sigsetjmp(unwind_buf, 1)) {
        should_unwind = 0;
        return 1;
    } else {
        should_unwind = 1;
        return 0;
    }
}

static inline void sigunwind_end()
{
    should_unwind = 0;
}

# 8 "/Users/bbarrows/repos/ish/emu/memory.h" 2

typedef dword_t page_t;

struct mem {
    atomic_uint changes;
    struct pt_entry **pgdir;
    int pgdir_used;

    wrlock_t lock;
};

void mem_init(struct mem *mem);

void mem_destroy(struct mem *mem);

struct pt_entry * mem_pt(struct mem *mem, page_t page);

void mem_next_page(struct mem *mem, page_t *page);

typedef dword_t pages_t;

struct data {
    page_t pgstart;
    page_t pgnum;
    char debugString[4096];

    int brads;
    void *data;
    size_t size;
    atomic_uint refcount;

    struct fd *fd;
    size_t file_offset;
    const char *name;
};
struct pt_entry {
    int brads;
    struct data *data;
    size_t offset;
    unsigned flags;
};
# 102 "/Users/bbarrows/repos/ish/emu/memory.h"
_Bool pt_is_hole(struct mem *mem, page_t start, pages_t pages);
page_t pt_find_hole(struct mem *mem, pages_t size);

int pt_map(struct mem *mem, page_t start, pages_t pages, void *memory, size_t offset, unsigned flags);

int pt_map_nothing(struct mem *mem, page_t page, pages_t pages, unsigned flags);

int pt_unmap(struct mem *mem, page_t start, pages_t pages);

int pt_unmap_always(struct mem *mem, page_t start, pages_t pages);

int pt_set_flags(struct mem *mem, page_t start, pages_t pages, int flags);

int pt_copy_on_write(struct mem *src, struct mem *dst, page_t start, page_t pages);

void * mem_ptr(struct mem *mem, addr_t addr, int type);
int mem_segv_reason(struct mem *mem, addr_t addr);

extern size_t real_page_size;
# 5 "/Users/bbarrows/repos/ish/jit/jit.h" 2
# 5 "/Users/bbarrows/repos/ish/jit/gen.h" 2
# 1 "/Users/bbarrows/repos/ish/emu/tlb.h" 1

#pragma clang module import Darwin.C.string /* clang -E: implicit import for #include <string.h> */

# 1 "/Users/bbarrows/repos/ish/debug.h" 1

#pragma clang module import Darwin.C.stdio /* clang -E: implicit import for #include <stdio.h> */
#pragma clang module import Darwin.C.stdlib /* clang -E: implicit import for #include <stdlib.h> */

void printk(const char *msg, ...);
void vprintk(const char *msg, va_list args);
# 74 "/Users/bbarrows/repos/ish/debug.h"
extern void (*die_handler)(const char *msg);
_Noreturn void die(const char *msg, ...);
# 7 "/Users/bbarrows/repos/ish/emu/tlb.h" 2

struct tlb_entry {
    page_t page;
    page_t page_if_writable;
    uintptr_t data_minus_addr;
};

struct tlb {
    struct mem *mem;
    page_t dirty_page;
    struct tlb_entry entries[(1 << 10)];
};

void tlb_init(struct tlb *tlb, struct mem *mem);
void tlb_free(struct tlb *tlb);
void tlb_flush(struct tlb *tlb);
void * tlb_handle_miss(struct tlb *tlb, addr_t addr, int type);

inline __attribute__((always_inline)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) void * __tlb_read_ptr(struct tlb *tlb, addr_t addr)
{
    struct tlb_entry entry = tlb->entries[(((addr >> 12) & ((1 << 10) - 1)) ^ (addr >> (12 + 10)))];
    if (entry.page == (addr & 0xfffff000)) {
        void *address = (void *)(entry.data_minus_addr + addr);
        (__builtin_expect(!(address != ((void *)0)), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish/emu/tlb.h", 33, "address != NULL") : (void)0);
        return address;
    }
    return tlb_handle_miss(tlb, addr, 0);
}

_Bool __tlb_read_cross_page(struct tlb *tlb, addr_t addr, char *out, unsigned size);
inline __attribute__((always_inline)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) _Bool tlb_read(struct tlb *tlb, addr_t addr, void *out, unsigned size)
{
    if (((addr) & ((1 << 12) - 1)) > (1 << 12) - size) return __tlb_read_cross_page(tlb, addr, out, size);
    void *ptr = __tlb_read_ptr(tlb, addr);
    if (ptr == ((void *)0)) return 0;
    __builtin___memcpy_chk(out, ptr, size, __builtin_object_size(out, 0));
    return 1;
}

inline __attribute__((always_inline)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) void * __tlb_write_ptr(struct tlb *tlb, addr_t addr)
{
    struct tlb_entry entry = tlb->entries[(((addr >> 12) & ((1 << 10) - 1)) ^ (addr >> (12 + 10)))];
    if (entry.page_if_writable == (addr & 0xfffff000)) {
        tlb->dirty_page = (addr & 0xfffff000);
        void *address = (void *)(entry.data_minus_addr + addr);
        (__builtin_expect(!(address != ((void *)0)), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish/emu/tlb.h", 54, "address != NULL") : (void)0);
        return address;
    }
    return tlb_handle_miss(tlb, addr, 1);
}

_Bool __tlb_write_cross_page(struct tlb *tlb, addr_t addr, const char *value, unsigned size);
inline __attribute__((always_inline)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) _Bool tlb_write(struct tlb *tlb, addr_t addr, const void *value, unsigned size)
{
    if (((addr) & ((1 << 12) - 1)) > (1 << 12) - size) return __tlb_write_cross_page(tlb, addr, value, size);
    void *ptr = __tlb_write_ptr(tlb, addr);
    if (ptr == ((void *)0)) return 0;
    __builtin___memcpy_chk(ptr, value, size, __builtin_object_size(ptr, 0));
    return 1;
}

# 6 "/Users/bbarrows/repos/ish/jit/gen.h" 2

struct gen_state {
    addr_t ip;
    struct jit_block *block;
    unsigned size;
    unsigned capacity;
    unsigned jump_ip[2];
    unsigned block_patch_ip;
};

void gen_start(addr_t addr, struct gen_state *state);
void gen_exit(struct gen_state *state);
void gen_end(struct gen_state *state);

int gen_step32(struct gen_state *state, struct tlb *tlb);
# 3 "/Users/bbarrows/repos/ish/jit/gen.c" 2
# 1 "/Users/bbarrows/repos/ish/emu/modrm.h" 1

# 1 "/Users/bbarrows/repos/ish/emu/cpu.h" 1

#pragma clang module import Darwin.C.stddef /* clang -E: implicit import for #include <stddef.h> */

# 1 "/Users/bbarrows/repos/ish/emu/float80.h" 1

#pragma clang module import Darwin.C.stdint /* clang -E: implicit import for #include <stdint.h> */
#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */

typedef struct {
    uint64_t signif;
    union {
        uint16_t signExp;
        struct {
            unsigned exp : 15;
            unsigned sign : 1;
        };
    };
} float80;

float80 f80_from_int(int64_t i);
int64_t f80_to_int(float80 f);
float80 f80_from_double(double d);
double f80_to_double(float80 f);

_Bool f80_isnan(float80 f);
_Bool f80_isinf(float80 f);
_Bool f80_iszero(float80 f);
_Bool f80_isdenormal(float80 f);
_Bool f80_is_supported(float80 f);

float80 f80_add(float80 a, float80 b);
float80 f80_sub(float80 a, float80 b);
float80 f80_mul(float80 a, float80 b);
float80 f80_div(float80 a, float80 b);
float80 f80_mod(float80 a, float80 b);
float80 f80_rem(float80 a, float80 b);

_Bool f80_lt(float80 a, float80 b);
_Bool f80_eq(float80 a, float80 b);
_Bool f80_uncomparable(float80 a, float80 b);

float80 f80_neg(float80 f);
float80 f80_abs(float80 f);

float80 f80_log2(float80 x);
float80 f80_sqrt(float80 x);

float80 f80_scale(float80 x, int scale);

enum f80_rounding_mode {
    round_to_nearest = 0,
    round_down       = 1,
    round_up         = 2,
    round_chop       = 3,
};
extern __thread enum f80_rounding_mode f80_rounding_mode;
# 7 "/Users/bbarrows/repos/ish/emu/cpu.h" 2

struct cpu_state;
struct tlb;
void cpu_run(struct cpu_state *cpu);
int cpu_step32(struct cpu_state *cpu, struct tlb *tlb);
int cpu_step16(struct cpu_state *cpu, struct tlb *tlb);

union xmm_reg {
    qword_t qw[2];
    dword_t dw[4];
};

struct cpu_state {
    struct mem *mem;
    struct jit *jit;
# 41 "/Users/bbarrows/repos/ish/emu/cpu.h"
    union { dword_t eax; word_t ax; struct { byte_t al; byte_t ah; }; };
    union { dword_t ebx; word_t bx; struct { byte_t bl; byte_t bh; }; };
    union { dword_t ecx; word_t cx; struct { byte_t cl; byte_t ch; }; };
    union { dword_t edx; word_t dx; struct { byte_t dl; byte_t dh; }; };
    union { dword_t esi; word_t si; };
    union { dword_t edi; word_t di; };
    union { dword_t ebp; word_t bp; };
    union { dword_t esp; word_t sp; };

    union xmm_reg xmm[8];

    dword_t eip;

    union {
        dword_t eflags;
        struct {
            unsigned int cf_bit : 1;
            unsigned int pad1_1 : 1;
            unsigned int pf : 1;
            unsigned int pad2_0 : 1;
            unsigned int af : 1;
            unsigned int pad3_0 : 1;
            unsigned int zf : 1;
            unsigned int sf : 1;
            unsigned int tf : 1;
            unsigned int if_ : 1;
            unsigned int df : 1;
            unsigned int of_bit : 1;
            unsigned int iopl : 2;
        };
    };

    dword_t df_offset;

    byte_t cf;
    byte_t of;

    dword_t res, op1, op2;
    union {
        struct {
            unsigned int pf_res : 1;
            unsigned int zf_res : 1;
            unsigned int sf_res : 1;
            unsigned int af_ops : 1;
        };

        byte_t flags_res;
    };

    float80 fp[8];
    union {
        word_t fsw;
        struct {
            unsigned int ie : 1;
            unsigned int de : 1;
            unsigned int ze : 1;
            unsigned int oe : 1;
            unsigned int ue : 1;
            unsigned int pe : 1;
            unsigned int stf : 1;
            unsigned int es : 1;
            unsigned int c0 : 1;
            unsigned int c1 : 1;
            unsigned int c2 : 1;
            unsigned top : 3;
            unsigned int c3 : 1;
            unsigned int b : 1;
        };
    };
    union {
        word_t fcw;
        struct {
            unsigned int im : 1;
            unsigned int dm : 1;
            unsigned int zm : 1;
            unsigned int om : 1;
            unsigned int um : 1;
            unsigned int pm : 1;
            unsigned int pad4 : 2;
            unsigned int pc : 2;
            unsigned int rc : 2;
            unsigned int y : 1;
        };
    };

    word_t gs;
    addr_t tls_ptr;

    addr_t segfault_addr;

    dword_t trapno;
};
# 159 "/Users/bbarrows/repos/ish/emu/cpu.h"
static inline void collapse_flags(struct cpu_state *cpu)
{
    cpu->zf = (cpu->zf_res ? cpu->res == 0 : cpu->zf);
    cpu->sf = (cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf);
    cpu->pf = (cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf);
    cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
    cpu->of_bit = cpu->of;
    cpu->cf_bit = cpu->cf;
    cpu->af = (cpu->af_ops ? ((cpu->op1 ^ cpu->op2 ^ cpu->res) >> 4) & 1 : cpu->af);
    cpu->af_ops = 0;
    cpu->pad1_1 = 1;
    cpu->pad2_0 = cpu->pad3_0 = 0;
    cpu->if_ = 1;
}

static inline void expand_flags(struct cpu_state *cpu)
{
    cpu->of = cpu->of_bit;
    cpu->cf = cpu->cf_bit;
    cpu->zf_res = cpu->sf_res = cpu->pf_res = cpu->af_ops = 0;
}

enum reg32 {
    reg_eax  = 0, reg_ecx, reg_edx, reg_ebx, reg_esp, reg_ebp, reg_esi, reg_edi, reg_count,
    reg_none = reg_count,
};

static inline const char * getRegisterString(enum reg32 reg)
{
    switch (reg) {
        case reg_eax: return "eax";
        case reg_ecx: return "ecx";
        case reg_edx: return "edx";
        case reg_ebx: return "ebx";
        case reg_esp: return "esp";
        case reg_ebp: return "ebp";
        case reg_esi: return "esi";
        case reg_edi: return "edi";
        case reg_none: return "?";
    }
}

static inline const char * get_register_string(enum reg32 reg)
{
    switch (reg) {
        case reg_eax: return "eax";
        case reg_ecx: return "ecx";
        case reg_edx: return "edx";
        case reg_ebx: return "ebx";
        case reg_esp: return "esp";
        case reg_ebp: return "ebp";
        case reg_esi: return "esi";
        case reg_edi: return "edi";
        case reg_none: return "?";
    }
}

static inline const char * reg32_name(enum reg32 reg)
{
    switch (reg) {
        case reg_eax: return "eax";
        case reg_ecx: return "ecx";
        case reg_edx: return "edx";
        case reg_ebx: return "ebx";
        case reg_esp: return "esp";
        case reg_ebp: return "ebp";
        case reg_esi: return "esi";
        case reg_edi: return "edi";
        case reg_none: return "?";
    }
}

# 7 "/Users/bbarrows/repos/ish/emu/modrm.h" 2

struct modrm {
    union {
        enum reg32 reg;
        int opcode;
    };
    enum {
        modrm_reg, modrm_mem, modrm_mem_si
    } type;
    union {
        enum reg32 base;
        int rm_opcode;
    };
    int32_t offset;
    enum reg32 index;
    enum {
        times_1 = 0,
        times_2 = 1,
        times_4 = 2,
    } shift;
};

enum {
    rm_sib    = reg_esp,
    rm_none   = reg_esp,
    rm_disp32 = reg_ebp,
};

static inline _Bool modrm_decode32(addr_t *ip, struct tlb *tlb, struct modrm *modrm)
{
    byte_t modrm_byte;
    if (!tlb_read(tlb, *ip, &(modrm_byte), sizeof(modrm_byte))) return 0; *ip += sizeof(modrm_byte);

    enum {
        mode_disp0,
        mode_disp8,
        mode_disp32,
        mode_reg,
    } mode = ((modrm_byte & 0b11000000) >> 6);
    modrm->type = modrm_mem;
    modrm->reg = ((modrm_byte & 0b00111000) >> 3);
    modrm->rm_opcode = ((modrm_byte & 0b00000111) >> 0);
    if (mode == mode_reg) {
        modrm->type = modrm_reg;
    } else if (modrm->rm_opcode == rm_disp32 && mode == mode_disp0) {
        modrm->base = reg_none;
        mode = mode_disp32;
    } else if (modrm->rm_opcode == rm_sib && mode != mode_reg) {
        byte_t sib_byte;
        if (!tlb_read(tlb, *ip, &(sib_byte), sizeof(sib_byte))) return 0; *ip += sizeof(sib_byte);
        modrm->base = ((sib_byte & 0b00000111) >> 0);

        if (modrm->rm_opcode == rm_disp32) {
            if (mode == mode_disp0) {
                modrm->base = reg_none;
                mode = mode_disp32;
            } else {
                modrm->base = reg_ebp;
            }
        }
        modrm->index = ((sib_byte & 0b00111000) >> 3);
        modrm->shift = ((sib_byte & 0b11000000) >> 6);
        if (modrm->index != rm_none) modrm->type = modrm_mem_si;
    }

    if (mode == mode_disp0) {
        modrm->offset = 0;
    } else if (mode == mode_disp8) {
        int8_t offset;
        if (!tlb_read(tlb, *ip, &(offset), sizeof(offset))) return 0; *ip += sizeof(offset);
        modrm->offset = offset;
    } else if (mode == mode_disp32) {
        int32_t offset;
        if (!tlb_read(tlb, *ip, &(offset), sizeof(offset))) return 0; *ip += sizeof(offset);
        modrm->offset = offset;
    }

    __use(0, reg32_name(modrm->reg), modrm->opcode);
    __use(0, reg32_name(modrm->base));
    if (modrm->type != modrm_reg) __use(0, modrm->offset < 0 ? "-" : "", modrm->offset);
    if (modrm->type == modrm_mem_si) __use(0, reg32_name(modrm->index), modrm->shift);

    return 1;
}

# 4 "/Users/bbarrows/repos/ish/jit/gen.c" 2
# 1 "/Users/bbarrows/repos/ish/emu/cpuid.h" 1

static inline void do_cpuid(dword_t *eax, dword_t *ebx, dword_t *ecx, dword_t *edx)
{
    dword_t leaf = *eax;
    switch (leaf) {
        case 0:
            *eax = 0x01;
            *ebx = 0x756e6547;
            *edx = 0x49656e69;
            *ecx = 0x6c65746e;
            break;
        default:
        case 1:
            *eax = 0x0;
            *ebx = 0x0;
            *ecx = 0b00000000000000000000000000000000;
            *edx = 0b00000000000000001000000000000000;
            break;
    }
}

# 5 "/Users/bbarrows/repos/ish/jit/gen.c" 2
# 1 "/Users/bbarrows/repos/ish/emu/fpu.h" 1

struct cpu_state;
struct fpu_env32;
struct fpu_state32;

typedef float  float32;
typedef double float64;

enum fpu_const {
    fconst_one   = 0,
    fconst_log2t = 1,
    fconst_log2e = 2,
    fconst_pi    = 3,
    fconst_log2  = 4,
    fconst_ln2   = 5,
    fconst_zero  = 6,
};
static float80 fpu_consts[] = {
    [fconst_one] = (float80)   { .signif = 0x8000000000000000, .signExp = 0x3fff },
    [fconst_log2t] = (float80) { .signif = 0xd49a784bcd1b8afe, .signExp = 0x4000 },
    [fconst_log2e] = (float80) { .signif = 0xb8aa3b295c17f0bc, .signExp = 0x3fff },
    [fconst_pi] = (float80)    { .signif = 0xc90fdaa22168c235, .signExp = 0x4000 },
    [fconst_log2] = (float80)  { .signif = 0x9a209a84fbcff799, .signExp = 0x3ffd },
    [fconst_ln2] = (float80)   { .signif = 0xb17217f7d1cf79ac, .signExp = 0x3ffe },
    [fconst_zero] = (float80)  { .signif = 0x0000000000000000, .signExp = 0x0000 },
};

void fpu_pop(struct cpu_state *cpu);
void fpu_xch(struct cpu_state *cpu, int i);
void fpu_incstp(struct cpu_state *cpu);

void fpu_st(struct cpu_state *cpu, int i);
void fpu_ist16(struct cpu_state *cpu, int16_t *i);
void fpu_ist32(struct cpu_state *cpu, int32_t *i);
void fpu_ist64(struct cpu_state *cpu, int64_t *i);
void fpu_stm32(struct cpu_state *cpu, float *f);
void fpu_stm64(struct cpu_state *cpu, double *f);
void fpu_stm80(struct cpu_state *cpu, float80 *f);

void fpu_ld(struct cpu_state *cpu, int i);
void fpu_ldc(struct cpu_state *cpu, enum fpu_const c);
void fpu_ild16(struct cpu_state *cpu, int16_t *i);
void fpu_ild32(struct cpu_state *cpu, int32_t *i);
void fpu_ild64(struct cpu_state *cpu, int64_t *i);
void fpu_ldm32(struct cpu_state *cpu, float *f);
void fpu_ldm64(struct cpu_state *cpu, double *f);
void fpu_ldm80(struct cpu_state *cpu, float80 *f);

void fpu_prem(struct cpu_state *cpu);
void fpu_rndint(struct cpu_state *cpu);
void fpu_scale(struct cpu_state *cpu);
void fpu_abs(struct cpu_state *cpu);
void fpu_chs(struct cpu_state *cpu);
void fpu_sqrt(struct cpu_state *cpu);
void fpu_yl2x(struct cpu_state *cpu);
void fpu_2xm1(struct cpu_state *cpu);

void fpu_com(struct cpu_state *cpu, int i);
void fpu_comm32(struct cpu_state *cpu, float *f);
void fpu_comm64(struct cpu_state *cpu, double *f);
void fpu_icom16(struct cpu_state *cpu, int16_t *i);
void fpu_icom32(struct cpu_state *cpu, int32_t *i);
void fpu_comi(struct cpu_state *cpu, int i);
void fpu_tst(struct cpu_state *cpu);

void fpu_add(struct cpu_state *cpu, int srci, int dsti);
void fpu_sub(struct cpu_state *cpu, int srci, int dsti);
void fpu_subr(struct cpu_state *cpu, int srci, int dsti);
void fpu_mul(struct cpu_state *cpu, int srci, int dsti);
void fpu_div(struct cpu_state *cpu, int srci, int dsti);
void fpu_divr(struct cpu_state *cpu, int srci, int dsti);
void fpu_iadd16(struct cpu_state *cpu, int16_t *i);
void fpu_isub16(struct cpu_state *cpu, int16_t *i);
void fpu_isubr16(struct cpu_state *cpu, int16_t *i);
void fpu_imul16(struct cpu_state *cpu, int16_t *i);
void fpu_idiv16(struct cpu_state *cpu, int16_t *i);
void fpu_idivr16(struct cpu_state *cpu, int16_t *i);
void fpu_iadd32(struct cpu_state *cpu, int32_t *i);
void fpu_isub32(struct cpu_state *cpu, int32_t *i);
void fpu_isubr32(struct cpu_state *cpu, int32_t *i);
void fpu_imul32(struct cpu_state *cpu, int32_t *i);
void fpu_idiv32(struct cpu_state *cpu, int32_t *i);
void fpu_idivr32(struct cpu_state *cpu, int32_t *i);
void fpu_addm32(struct cpu_state *cpu, float *f);
void fpu_subm32(struct cpu_state *cpu, float *f);
void fpu_subrm32(struct cpu_state *cpu, float *f);
void fpu_mulm32(struct cpu_state *cpu, float *f);
void fpu_divm32(struct cpu_state *cpu, float *f);
void fpu_divrm32(struct cpu_state *cpu, float *f);
void fpu_addm64(struct cpu_state *cpu, double *f);
void fpu_subm64(struct cpu_state *cpu, double *f);
void fpu_subrm64(struct cpu_state *cpu, double *f);
void fpu_mulm64(struct cpu_state *cpu, double *f);
void fpu_divm64(struct cpu_state *cpu, double *f);
void fpu_divrm64(struct cpu_state *cpu, double *f);

void fpu_patan(struct cpu_state *cpu);
void fpu_sin(struct cpu_state *cpu);
void fpu_cos(struct cpu_state *cpu);
void fpu_xam(struct cpu_state *cpu);

void fpu_stcw16(struct cpu_state *cpu, uint16_t *i);
void fpu_ldcw16(struct cpu_state *cpu, uint16_t *i);
void fpu_stenv32(struct cpu_state *cpu, struct fpu_env32 *env);
void fpu_ldenv32(struct cpu_state *cpu, struct fpu_env32 *env);
void fpu_save32(struct cpu_state *cpu, struct fpu_state32 *state);
void fpu_restore32(struct cpu_state *cpu, struct fpu_state32 *state);
# 6 "/Users/bbarrows/repos/ish/jit/gen.c" 2
# 1 "/Users/bbarrows/repos/ish/emu/sse.h" 1

void vec_compare32(struct cpu_state *UNUSED_cpu __attribute__((unused)), float *f2, float *f1);
# 26 "/Users/bbarrows/repos/ish/emu/sse.h"
void vec_load32(struct cpu_state *UNUSED_cpu __attribute__((unused)), const union xmm_reg *src, union xmm_reg *dst);
void vec_load64(struct cpu_state *UNUSED_cpu __attribute__((unused)), const union xmm_reg *src, union xmm_reg *dst);
void vec_load128(struct cpu_state *UNUSED_cpu __attribute__((unused)), const union xmm_reg *src, union xmm_reg *dst);

void vec_zload32(struct cpu_state *UNUSED_cpu __attribute__((unused)), const union xmm_reg *src, union xmm_reg *dst);
void vec_zload64(struct cpu_state *UNUSED_cpu __attribute__((unused)), const union xmm_reg *src, union xmm_reg *dst);
void vec_zload128(struct cpu_state *UNUSED_cpu __attribute__((unused)), const union xmm_reg *src, union xmm_reg *dst);

void vec_store32(struct cpu_state *UNUSED_cpu __attribute__((unused)), union xmm_reg *src, const union xmm_reg *dst);
void vec_store64(struct cpu_state *UNUSED_cpu __attribute__((unused)), union xmm_reg *src, const union xmm_reg *dst);
void vec_store128(struct cpu_state *UNUSED_cpu __attribute__((unused)), union xmm_reg *src, const union xmm_reg *dst);

void vec_imm_shiftr64(struct cpu_state *UNUSED_cpu __attribute__((unused)), const uint8_t amount, union xmm_reg *src);
void vec_xor128(struct cpu_state *cpu, union xmm_reg *src, union xmm_reg *dst);
# 7 "/Users/bbarrows/repos/ish/jit/gen.c" 2
# 1 "/Users/bbarrows/repos/ish/emu/interrupt.h" 1
# 8 "/Users/bbarrows/repos/ish/jit/gen.c" 2

# 1 "/Users/bbarrows/repos/ish/kernel/task.h" 1

#pragma clang module import Darwin.POSIX.pthread.pthread /* clang -E: implicit import for #include <pthread.h> */

# 1 "/Users/bbarrows/repos/ish/kernel/mm.h" 1

struct mm {
    atomic_uint refcount;
    struct mem mem;

    addr_t vdso;
    addr_t start_brk;
    addr_t brk;

    addr_t argv_start;
    addr_t argv_end;
    addr_t env_start;
    addr_t env_end;
    addr_t stack_start;
    struct fd *exefile;
};

struct mm * mm_new(void);

struct mm * mm_copy(struct mm *mm);

void mm_retain(struct mm *mem);

void mm_release(struct mm *mem);
# 7 "/Users/bbarrows/repos/ish/kernel/task.h" 2
# 1 "/Users/bbarrows/repos/ish/kernel/fs.h" 1

# 1 "/Users/bbarrows/repos/ish/fs/stat.h" 1

struct statbuf {
    qword_t dev;
    qword_t inode;
    dword_t mode;
    dword_t nlink;
    dword_t uid;
    dword_t gid;
    qword_t rdev;
    qword_t size;
    dword_t blksize;
    qword_t blocks;
    dword_t atime;
    dword_t atime_nsec;
    dword_t mtime;
    dword_t mtime_nsec;
    dword_t ctime;
    dword_t ctime_nsec;
};

struct oldstat {
    word_t dev;
    word_t ino;
    word_t mode;
    word_t nlink;
    word_t uid;
    word_t gid;
    word_t rdev;
    uint_t size;
    uint_t atime;
    uint_t mtime;
    uint_t ctime;
};

struct newstat {
    dword_t dev;
    dword_t ino;
    word_t mode;
    word_t nlink;
    word_t uid;
    word_t gid;
    dword_t rdev;
    dword_t size;
    dword_t blksize;
    dword_t blocks;
    dword_t atime;
    dword_t atime_nsec;
    dword_t mtime;
    dword_t mtime_nsec;
    dword_t ctime;
    dword_t ctime_nsec;
    char pad[8];
};

struct newstat64 {
    qword_t dev;
    dword_t _pad1;
    dword_t fucked_ino;
    dword_t mode;
    dword_t nlink;
    dword_t uid;
    dword_t gid;
    qword_t rdev;
    dword_t _pad2;
    qword_t size;
    dword_t blksize;
    qword_t blocks;
    dword_t atime;
    dword_t atime_nsec;
    dword_t mtime;
    dword_t mtime_nsec;
    dword_t ctime;
    dword_t ctime_nsec;
    qword_t ino;
} __attribute__((packed));

struct statfsbuf {
    long type;
    long bsize;
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    uint64_t fsid;
    long namelen;
    long frsize;
    long flags;
    long spare[4];
};

struct statfs_ {
    uint_t type;
    uint_t bsize;
    uint_t blocks;
    uint_t bfree;
    uint_t bavail;
    uint_t files;
    uint_t ffree;
    uint64_t fsid;
    uint_t namelen;
    uint_t frsize;
    uint_t flags;
    uint_t spare[4];
};

struct statfs64_ {
    uint_t type;
    uint_t bsize;
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    uint64_t fsid;
    uint_t namelen;
    uint_t frsize;
    uint_t flags;
    uint_t pad[4];
} __attribute__((packed));
# 7 "/Users/bbarrows/repos/ish/kernel/fs.h" 2
# 1 "/Users/bbarrows/repos/ish/fs/dev.h" 1

#pragma clang module import Darwin.POSIX.sys.types /* clang -E: implicit import for #include <sys/types.h> */

# 1 "/Users/bbarrows/repos/ish/fs/fd.h" 1

#pragma clang module import Darwin.POSIX.dirent /* clang -E: implicit import for #include <dirent.h> */

# 1 "/Users/bbarrows/repos/ish/util/bits.h" 1

typedef void bits_t;

static inline _Bool bit_test(size_t i, bits_t *data)
{
    char *c = data;
    return c[i >> 3] & (1 << (i & 7)) ? 1 : 0;
}

static inline void bit_set(size_t i, bits_t *data)
{
    char *c = data;
    c[i >> 3] |= 1 << (i & 7);
}

static inline void bit_clear(size_t i, bits_t *data)
{
    char *c = data;
    c[i >> 3] &= ~(1 << (i & 7));
}

# 8 "/Users/bbarrows/repos/ish/fs/fd.h" 2

# 1 "/Users/bbarrows/repos/ish/fs/proc.h" 1

struct proc_entry {
    struct proc_dir_entry *meta;
    pid_t_ pid;
    sdword_t fd;
};

struct proc_data {
    char *data;
    size_t size;
    size_t capacity;
};

struct proc_dir_entry {
    const char *name;
    mode_t_ mode;

    void (*getname)(struct proc_entry *entry, char *buf);

    int (*show)(struct proc_entry *entry, struct proc_data *data);

    int (*readlink)(struct proc_entry *entry, char *buf);

    struct proc_dir_entry *children;
    size_t children_sizeof;

    _Bool (*readdir)(struct proc_entry *entry, unsigned long *index, struct proc_entry *next_entry);

    struct proc_dir_entry *parent;
    int inode;
};

extern struct proc_dir_entry proc_root;
extern struct proc_dir_entry proc_pid;

mode_t_ proc_entry_mode(struct proc_entry *entry);
void proc_entry_getname(struct proc_entry *entry, char *buf);
int proc_entry_stat(struct proc_entry *entry, struct statbuf *stat);

_Bool proc_dir_read(struct proc_entry *entry, unsigned long *index, struct proc_entry *next_entry);

void proc_buf_write(struct proc_data *buf, const void *data, size_t size);
void proc_printf(struct proc_data *buf, const char *format, ...);
# 10 "/Users/bbarrows/repos/ish/fs/fd.h" 2
# 1 "/Users/bbarrows/repos/ish/fs/sockrestart.h" 1
# 15 "/Users/bbarrows/repos/ish/fs/sockrestart.h"
#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */

struct fd;

void sockrestart_begin_listen(struct fd *sock);
void sockrestart_end_listen(struct fd *sock);
void sockrestart_begin_listen_wait(struct fd *sock);
void sockrestart_end_listen_wait(struct fd *sock);
_Bool sockrestart_should_restart_listen_wait(void);
void sockrestart_on_suspend(void);
void sockrestart_on_resume(void);

struct fd_sockrestart {
    struct list listen;
};

struct task_sockrestart {
    int count;
    _Bool punt;
    struct list listen;
};
# 11 "/Users/bbarrows/repos/ish/fs/fd.h" 2

struct fd {
    atomic_uint refcount;
    unsigned flags;
    mode_t_ type;
    const struct fd_ops *ops;
    struct list poll_fds;
    lock_t poll_lock;
    unsigned long offset;

    union {
        struct {
            struct tty *tty;

            struct list tty_other_fds;
        };
        struct {
            struct poll *poll;
        } epollfd;
        struct {
            uint64_t val;
        } eventfd;
        struct {
            struct timer *timer;
            uint64_t expirations;
        } timerfd;
        struct {
            int domain;
            int type;
            int protocol;

            struct inode_data *unix_name_inode;
            struct unix_abstract *unix_name_abstract;

            struct fd *unix_peer;
            cond_t unix_got_peer;

            struct list unix_scm;
            struct ucred_ {
                pid_t_ pid;
                uid_t_ uid;
                uid_t_ gid;
            } unix_cred;
        } socket;

        struct {
            uint64_t generation;

            void *buffer;

            size_t buffer_cap;

            size_t buffer_len;
        } clipboard;

        void *data;
    };

    union {
        struct {
            struct proc_entry entry;
            unsigned dir_index;
            struct proc_data data;
        } proc;
        struct {
            int num;
        } devpts;
        struct {
            struct tmp_dirent *dirent;
            struct tmp_dirent *dir_pos;
        } tmpfs;
        void *fs_data;
    };

    struct mount *mount;
    int real_fd;
    DIR *dir;
    struct inode_data *inode;
    ino_t fake_inode;
    struct statbuf stat;
    struct fd_sockrestart sockrestart;

    lock_t lock;
    cond_t cond;
};

typedef sdword_t fd_t;

struct fd * fd_create(const struct fd_ops *ops);
struct fd * fd_retain(struct fd *fd);
int fd_close(struct fd *fd);

int fd_getflags(struct fd *fd);
int fd_setflags(struct fd *fd, int flags);

struct dir_entry {
    qword_t inode;
    char name[255 + 1];
};

struct fd_ops {
    ssize_t (*read)(struct fd *fd, void *buf, size_t bufsize);
    ssize_t (*write)(struct fd *fd, const void *buf, size_t bufsize);
    ssize_t (*pread)(struct fd *fd, void *buf, size_t bufsize, off_t off);
    ssize_t (*pwrite)(struct fd *fd, const void *buf, size_t bufsize, off_t off);
    off_t_ (*lseek)(struct fd *fd, off_t_ off, int whence);

    int (*readdir)(struct fd *fd, struct dir_entry *entry);

    unsigned long (*telldir)(struct fd *fd);

    void (*seekdir)(struct fd *fd, unsigned long ptr);

    int (*mmap)(struct fd *fd, struct mem *mem, page_t start, pages_t pages, off_t offset, int prot, int flags);

    int (*poll)(struct fd *fd);

    ssize_t (*ioctl_size)(int cmd);

    int (*ioctl)(struct fd *fd, int cmd, void *arg);

    int (*fsync)(struct fd *fd);
    int (*close)(struct fd *fd);

    int (*getflags)(struct fd *fd);

    int (*setflags)(struct fd *fd, dword_t arg);
};

struct fdtable {
    atomic_uint refcount;
    unsigned size;
    struct fd **files;
    bits_t *cloexec;
    lock_t lock;
};

struct fdtable * fdtable_new(int size);
void fdtable_release(struct fdtable *table);
struct fdtable * fdtable_copy(struct fdtable *table);
void fdtable_free(struct fdtable *table);
void fdtable_do_cloexec(struct fdtable *table);
struct fd * fdtable_get(struct fdtable *table, fd_t f);

struct fd * f_get(fd_t f);

fd_t f_install(struct fd *fd, int flags);
int f_close(fd_t f);
# 9 "/Users/bbarrows/repos/ish/fs/dev.h" 2

typedef uint32_t dev_t_;

static inline dev_t_ dev_make(int major, int minor)
{
    return ((minor & 0xfff00) << 12) | (major << 8) | (minor & 0xff);
}

static inline int dev_major(dev_t_ dev)
{
    return (dev & 0xfff00) >> 8;
}

static inline int dev_minor(dev_t_ dev)
{
    return ((dev & 0xfff00000) >> 12) | (dev & 0xff);
}

static inline dev_t dev_real_from_fake(dev_t_ dev)
{
    return ((dev_t)(((dev_major(dev)) << 24) | (dev_minor(dev))));
}

static inline dev_t_ dev_fake_from_real(dev_t dev)
{
    return dev_make(((int32_t)(((u_int32_t)(dev) >> 24) & 0xff)), ((int32_t)((dev) & 0xffffff)));
}

struct dev_ops {
    int (*open)(int major, int minor, struct fd *fd);
    struct fd_ops fd;
};

extern struct dev_ops *block_devs[];
extern struct dev_ops *char_devs[];

int dev_open(int major, int minor, int type, struct fd *fd);

extern struct dev_ops null_dev;
# 8 "/Users/bbarrows/repos/ish/kernel/fs.h" 2

#pragma clang module import Darwin.POSIX.dirent /* clang -E: implicit import for #include <dirent.h> */
#pragma clang module import SQLite3 /* clang -E: implicit import for #include <sqlite3.h> */

struct fs_info {
    atomic_uint refcount;
    mode_t_ umask;
    struct fd *pwd;
    struct fd *root;
    lock_t lock;
};
struct fs_info * fs_info_new(void);
struct fs_info * fs_info_copy(struct fs_info *fs);
void fs_info_release(struct fs_info *fs);

void fs_chdir(struct fs_info *fs, struct fd *pwd);

struct attr {
    enum attr_type {
        attr_uid,
        attr_gid,
        attr_mode,
        attr_size,
    } type;
    union {
        uid_t_ uid;
        uid_t_ gid;
        mode_t_ mode;
        off_t_ size;
    };
};

struct fd * generic_open(const char *path, int flags, int mode);
struct fd * generic_openat(struct fd *at, const char *path, int flags, int mode);
int generic_getpath(struct fd *fd, char *buf);
int generic_linkat(struct fd *src_at, const char *src_raw, struct fd *dst_at, const char *dst_raw);
int generic_unlinkat(struct fd *at, const char *path);
int generic_rmdirat(struct fd *at, const char *path);
int generic_renameat(struct fd *src_at, const char *src, struct fd *dst_at, const char *dst);
int generic_symlinkat(const char *target, struct fd *at, const char *link);
int generic_mknodat(struct fd *at, const char *path, mode_t_ mode, dev_t_ dev);

int generic_accessat(struct fd *dirfd, const char *path, int mode);
int generic_statat(struct fd *at, const char *path, struct statbuf *stat, _Bool follow_links);
int generic_setattrat(struct fd *at, const char *path, struct attr attr, _Bool follow_links);
int generic_utime(struct fd *at, const char *path, struct timespec atime, struct timespec mtime, _Bool follow_links);
ssize_t generic_readlinkat(struct fd *at, const char *path, char *buf, size_t bufsize);
int generic_mkdirat(struct fd *at, const char *path, mode_t_ mode);

int access_check(struct statbuf *stat, int check);

struct mount {
    const char *point;
    const char *source;
    int flags;
    const struct fs_ops *fs;
    unsigned refcount;
    struct list mounts;

    int root_fd;
    union {
        void *data;
        struct {
            sqlite3 *db;
            struct {
                sqlite3_stmt *begin;
                sqlite3_stmt *commit;
                sqlite3_stmt *rollback;
                sqlite3_stmt *path_get_inode;
                sqlite3_stmt *path_read_stat;
                sqlite3_stmt *path_create_stat;
                sqlite3_stmt *path_create_path;
                sqlite3_stmt *inode_read_stat;
                sqlite3_stmt *inode_write_stat;
                sqlite3_stmt *path_link;
                sqlite3_stmt *path_unlink;
                sqlite3_stmt *path_rename;
                sqlite3_stmt *path_from_inode;
                sqlite3_stmt *try_cleanup_inode;
            } stmt;
            lock_t lock;
        };
    };
};
extern lock_t mounts_lock;

struct mount * mount_find(char *path);
void mount_retain(struct mount *mount);
void mount_release(struct mount *mount);

int do_mount(const struct fs_ops *fs, const char *source, const char *point, int flags);
int do_umount(const char *point);
int mount_remove(struct mount *mount);
extern struct list mounts;
# 134 "/Users/bbarrows/repos/ish/kernel/fs.h"
struct fs_ops {
    const char *name;
    int magic;

    int (*mount)(struct mount *mount);
    int (*umount)(struct mount *mount);
    int (*statfs)(struct mount *mount, struct statfsbuf *stat);

    struct fd * (*open)(struct mount *mount, const char *path, int flags, int mode);
    ssize_t (*readlink)(struct mount *mount, const char *path, char *buf, size_t bufsize);

    int (*link)(struct mount *mount, const char *src, const char *dst);
    int (*unlink)(struct mount *mount, const char *path);
    int (*rmdir)(struct mount *mount, const char *path);
    int (*rename)(struct mount *mount, const char *src, const char *dst);
    int (*symlink)(struct mount *mount, const char *target, const char *link);
    int (*mknod)(struct mount *mount, const char *path, mode_t_ mode, dev_t_ dev);
    int (*mkdir)(struct mount *mount, const char *path, mode_t_ mode);

    int (*close)(struct fd *fd);

    int (*stat)(struct mount *mount, const char *path, struct statbuf *stat);
    int (*fstat)(struct fd *fd, struct statbuf *stat);
    int (*setattr)(struct mount *mount, const char *path, struct attr attr);
    int (*fsetattr)(struct fd *fd, struct attr attr);
    int (*utime)(struct mount *mount, const char *path, struct timespec atime, struct timespec mtime);

    int (*getpath)(struct fd *fd, char *buf);

    int (*flock)(struct fd *fd, int operation);

    void (*inode_orphaned)(struct mount *mount, ino_t inode);
};

struct mount * find_mount_and_trim_path(char *path);
const char * fix_path(const char *path);

extern const struct fd_ops realfs_fdops;

int realfs_truncate(struct mount *mount, const char *path, off_t_ size);
int realfs_utime(struct mount *mount, const char *path, struct timespec atime, struct timespec mtime);

int realfs_statfs(struct mount *mount, struct statfsbuf *stat);
int realfs_flock(struct fd *fd, int operation);
int realfs_getpath(struct fd *fd, char *buf);
ssize_t realfs_read(struct fd *fd, void *buf, size_t bufsize);
ssize_t realfs_write(struct fd *fd, const void *buf, size_t bufsize);
int realfs_poll(struct fd *fd);
int realfs_getflags(struct fd *fd);
int realfs_setflags(struct fd *fd, dword_t arg);
ssize_t realfs_ioctl_size(int cmd);
int realfs_ioctl(struct fd *fd, int cmd, void *arg);
int realfs_close(struct fd *fd);

struct fd * adhoc_fd_create(const struct fd_ops *ops);

extern const struct fs_ops realfs;
extern const struct fs_ops procfs;
extern const struct fs_ops fakefs;
extern const struct fs_ops devptsfs;
extern const struct fs_ops tmpfs;
# 8 "/Users/bbarrows/repos/ish/kernel/task.h" 2
# 1 "/Users/bbarrows/repos/ish/kernel/signal.h" 1

struct task;

typedef qword_t sigset_t_;
# 18 "/Users/bbarrows/repos/ish/kernel/signal.h"
struct sigaction_ {
    addr_t handler;
    dword_t flags;
    addr_t restorer;
    sigset_t_ mask;
} __attribute__((packed));
# 67 "/Users/bbarrows/repos/ish/kernel/signal.h"
union sigval_ {
    int_t sv_int;
    addr_t sv_ptr;
};

struct siginfo_ {
    int_t sig;
    int_t sig_errno;
    int_t code;
    union {
        struct {
            pid_t_ pid;
            uid_t_ uid;
        } kill;
        struct {
            pid_t_ pid;
            uid_t_ uid;
            int_t status;
            clock_t_ utime;
            clock_t_ stime;
        } child;
        struct {
            addr_t addr;
        } fault;
        struct {
            addr_t addr;
            int_t syscall;
        } sigsys;
    };
};

static const struct siginfo_ SIGINFO_NIL = {
    .code = 128,
};

struct sigqueue {
    struct list queue;
    struct siginfo_ info;
};

void send_signal(struct task *task, int sig, struct siginfo_ info);

void deliver_signal(struct task *task, int sig, struct siginfo_ info);

_Bool try_self_signal(int sig);

int send_group_signal(dword_t pgid, int sig, struct siginfo_ info);

void receive_signals(void);

void sigmask_set_temp(sigset_t_ mask);

struct sighand {
    atomic_uint refcount;
    struct sigaction_ action[64];
    addr_t altstack;
    dword_t altstack_size;
    lock_t lock;
};
struct sighand * sighand_new(void);
struct sighand * sighand_copy(struct sighand *sighand);
void sighand_release(struct sighand *sighand);

dword_t sys_rt_sigaction(dword_t signum, addr_t action_addr, addr_t oldaction_addr, dword_t sigset_size);
dword_t sys_sigaction(dword_t signum, addr_t action_addr, addr_t oldaction_addr);
dword_t sys_rt_sigreturn(void);
dword_t sys_sigreturn(void);

typedef uint64_t sigset_t_;
dword_t sys_rt_sigprocmask(dword_t how, addr_t set, addr_t oldset, dword_t size);
int_t sys_rt_sigpending(addr_t set_addr);

static inline sigset_t_ sig_mask(int sig)
{
    (__builtin_expect(!(sig >= 1 && sig < 64), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish/kernel/signal.h", 148, "sig >= 1 && sig < NUM_SIGS") : (void)0);
    return 1l << (sig - 1);
}

static inline _Bool sigset_has(sigset_t_ set, int sig)
{
    return !!(set & sig_mask(sig));
}

static inline void sigset_add(sigset_t_ *set, int sig)
{
    *set |= sig_mask(sig);
}

static inline void sigset_del(sigset_t_ *set, int sig)
{
    *set &= ~sig_mask(sig);
}

struct stack_t_ {
    addr_t stack;
    dword_t flags;
    dword_t size;
};

dword_t sys_sigaltstack(addr_t ss, addr_t old_ss);

int_t sys_rt_sigsuspend(addr_t mask_addr, uint_t size);
int_t sys_pause(void);
int_t sys_rt_sigtimedwait(addr_t set_addr, addr_t info_addr, addr_t timeout_addr, uint_t set_size);

dword_t sys_kill(pid_t_ pid, dword_t sig);
dword_t sys_tkill(pid_t_ tid, dword_t sig);
dword_t sys_tgkill(pid_t_ tgid, pid_t_ tid, dword_t sig);

struct sigcontext_ {
    word_t gs, __gsh;
    word_t fs, __fsh;
    word_t es, __esh;
    word_t ds, __dsh;
    dword_t di;
    dword_t si;
    dword_t bp;
    dword_t sp;
    dword_t bx;
    dword_t dx;
    dword_t cx;
    dword_t ax;
    dword_t trapno;
    dword_t err;
    dword_t ip;
    word_t cs, __csh;
    dword_t flags;
    dword_t sp_at_signal;
    word_t ss, __ssh;

    dword_t fpstate;
    dword_t oldmask;
    dword_t cr2;
};

struct ucontext_ {
    uint_t flags;
    uint_t link;
    struct stack_t_ stack;
    struct sigcontext_ mcontext;
    sigset_t_ sigmask;
} __attribute__((packed));

struct fpreg_ {
    word_t significand[4];
    word_t exponent;
};

struct fpxreg_ {
    word_t significand[4];
    word_t exponent;
    word_t padding[3];
};

struct xmmreg_ {
    uint32_t element[4];
};

struct fpstate_ {
    dword_t cw;
    dword_t sw;
    dword_t tag;
    dword_t ipoff;
    dword_t cssel;
    dword_t dataoff;
    dword_t datasel;
    struct fpreg_ st[8];
    word_t status;
    word_t magic;

    dword_t _fxsr_env[6];
    dword_t mxcsr;
    dword_t reserved;
    struct fpxreg_ fxsr_st[8];
    struct xmmreg_ xmm[8];
    dword_t padding[56];
};

struct sigframe_ {
    addr_t restorer;
    dword_t sig;
    struct sigcontext_ sc;
    struct fpstate_ fpstate;
    dword_t extramask;
    char retcode[8];
};

struct rt_sigframe_ {
    addr_t restorer;
    int_t sig;
    addr_t pinfo;
    addr_t puc;
    union {
        struct siginfo_ info;
        char __pad[128];
    };
    struct ucontext_ uc;
    char retcode[8];
};

extern int xsave_extra;
extern int fxsave_extra;
# 9 "/Users/bbarrows/repos/ish/kernel/task.h" 2
# 1 "/Users/bbarrows/repos/ish/kernel/resource.h" 1

# 1 "/Users/bbarrows/repos/ish/kernel/time.h" 1

dword_t sys_time(addr_t time_out);
dword_t sys_stime(addr_t time);

dword_t sys_clock_gettime(dword_t clock, addr_t tp);
dword_t sys_clock_settime(dword_t clock, addr_t tp);
dword_t sys_clock_getres(dword_t clock, addr_t res_addr);

struct timeval_ {
    dword_t sec;
    dword_t usec;
};
struct timespec_ {
    dword_t sec;
    dword_t nsec;
};
struct timezone_ {
    dword_t minuteswest;
    dword_t dsttime;
};

static inline clock_t_ clock_from_timeval(struct timeval_ timeval)
{
    return timeval.sec * 100 + timeval.usec / 10000;
}

struct itimerval_ {
    struct timeval_ interval;
    struct timeval_ value;
};

struct itimerspec_ {
    struct timespec_ interval;
    struct timespec_ value;
};

struct tms_ {
    clock_t_ tms_utime;
    clock_t_ tms_stime;
    clock_t_ tms_cutime;
    clock_t_ tms_cstime;
};

int_t sys_setitimer(int_t which, addr_t new_val, addr_t old_val);
uint_t sys_alarm(uint_t seconds);
dword_t sys_times(addr_t tbuf);
dword_t sys_nanosleep(addr_t req, addr_t rem);
dword_t sys_gettimeofday(addr_t tv, addr_t tz);
dword_t sys_settimeofday(addr_t tv, addr_t tz);

fd_t sys_timerfd_create(int_t clockid, int_t flags);
int_t sys_timerfd_settime(fd_t f, int_t flags, addr_t new_value_addr, addr_t old_value_addr);
# 4 "/Users/bbarrows/repos/ish/kernel/resource.h" 2

typedef qword_t rlim_t_;
typedef dword_t rlim32_t_;

struct rlimit_ {
    rlim_t_ cur;
    rlim_t_ max;
};

struct rlimit32_ {
    rlim32_t_ cur;
    rlim32_t_ max;
};
# 37 "/Users/bbarrows/repos/ish/kernel/resource.h"
dword_t sys_getrlimit32(dword_t resource, addr_t rlim_addr);
dword_t sys_setrlimit32(dword_t resource, addr_t rlim_addr);
dword_t sys_prlimit64(pid_t_ pid, dword_t resource, addr_t new_limit_addr, addr_t old_limit_addr);
dword_t sys_old_getrlimit32(dword_t resource, addr_t rlim_addr);

rlim_t_ rlimit(int resource);

struct rusage_ {
    struct timeval_ utime;
    struct timeval_ stime;
    dword_t maxrss;
    dword_t ixrss;
    dword_t idrss;
    dword_t isrss;
    dword_t minflt;
    dword_t majflt;
    dword_t nswap;
    dword_t inblock;
    dword_t oublock;
    dword_t msgsnd;
    dword_t msgrcv;
    dword_t nsignals;
    dword_t nvcsw;
    dword_t nivcsw;
};

struct rusage_ rusage_get_current(void);
void rusage_add(struct rusage_ *dst, struct rusage_ *src);

dword_t sys_getrusage(dword_t who, addr_t rusage_addr);

int_t sys_sched_getaffinity(pid_t_ pid, dword_t cpusetsize, addr_t cpuset_addr);
int_t sys_sched_setaffinity(pid_t_ pid, dword_t cpusetsize, addr_t cpuset_addr);
int_t sys_getpriority(int_t which, pid_t_ who);
int_t sys_setpriority(int_t which, pid_t_ who, int_t prio);

int_t sys_sched_getparam(pid_t_ pid, addr_t param_addr);
int_t sys_sched_getscheduler(pid_t_ UNUSED_pid __attribute__((unused)));
int_t sys_sched_setscheduler(pid_t_ UNUSED_pid __attribute__((unused)), int_t policy, addr_t param_addr);
int_t sys_sched_get_priority_max(int_t policy);
# 10 "/Users/bbarrows/repos/ish/kernel/task.h" 2

# 1 "/Users/bbarrows/repos/ish/util/timer.h" 1

#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */
#pragma clang module import Darwin.C.time /* clang -E: implicit import for #include <time.h> */
#pragma clang module import Darwin.POSIX.pthread.pthread /* clang -E: implicit import for #include <pthread.h> */
# 1 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 1 3 4
# 42 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 3 4
#pragma clang module import Darwin.cdefs /* clang -E: implicit import for #include <sys/cdefs.h> */
# 76 "/Applications/Xcode11.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.2.sdk/usr/include/assert.h" 3 4
void __assert_rtn(const char *, const char *, int, const char *) __attribute__((__noreturn__)) __attribute__((__cold__)) __attribute__((__disable_tail_calls__));
# 8 "/Users/bbarrows/repos/ish/util/timer.h" 2

static inline struct timespec timespec_now(clockid_t clockid)
{
    (__builtin_expect(!(clockid == _CLOCK_MONOTONIC || clockid == _CLOCK_REALTIME), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish/util/timer.h", 11, "clockid == CLOCK_MONOTONIC || clockid == CLOCK_REALTIME") : (void)0);
    struct timespec now;
    clock_gettime(clockid, &now);
    return now;
}

static inline struct timespec timespec_add(struct timespec x, struct timespec y)
{
    x.tv_sec += y.tv_sec;
    x.tv_nsec += y.tv_nsec;
    if (x.tv_nsec >= 1000000000) {
        x.tv_nsec -= 1000000000;
        x.tv_sec++;
    }
    return x;
}

static inline struct timespec timespec_subtract(struct timespec x, struct timespec y)
{
    struct timespec result;
    if (x.tv_nsec < y.tv_nsec) {
        x.tv_sec -= 1;
        x.tv_nsec += 1000000000;
    }
    result.tv_sec = x.tv_sec - y.tv_sec;
    result.tv_nsec = x.tv_nsec - y.tv_nsec;
    return result;
}

static inline _Bool timespec_is_zero(struct timespec ts)
{
    return ts.tv_sec == 0 && ts.tv_nsec == 0;
}

static inline _Bool timespec_positive(struct timespec ts)
{
    return ts.tv_sec > 0 || (ts.tv_sec == 0 && ts.tv_nsec > 0);
}

typedef void (*timer_callback_t)(void *data);
struct timer {
    clockid_t clockid;
    struct timespec start;
    struct timespec end;
    struct timespec interval;

    _Bool running;
    pthread_t thread;
    timer_callback_t callback;
    void *data;
    lock_t lock;
    _Bool dead;
};

struct timer * timer_new(clockid_t clockid, timer_callback_t callback, void *data);
void timer_free(struct timer *timer);

struct timer_spec {
    struct timespec value;
    struct timespec interval;
};
int timer_set(struct timer *timer, struct timer_spec spec, struct timer_spec *oldspec);
# 13 "/Users/bbarrows/repos/ish/kernel/task.h" 2

struct task {
    struct cpu_state cpu;
    struct mm *mm;
    struct mem *mem;
    pthread_t thread;
    uint64_t threadid;

    struct tgroup *group;
    struct list group_links;
    pid_t_ pid, tgid;
    uid_t_ uid, gid;
    uid_t_ euid, egid;
    uid_t_ suid, sgid;

    unsigned ngroups;
    uid_t_ groups[32];
    char comm[16];
    _Bool did_exec;

    struct fdtable *files;
    struct fs_info *fs;

    struct sighand *sighand;
    sigset_t_ blocked;
    sigset_t_ pending;
    sigset_t_ waiting;
    struct list queue;
    cond_t pause;

    sigset_t_ saved_mask;
    _Bool has_saved_mask;

    struct task *parent;
    struct list children;
    struct list siblings;

    addr_t clear_tid;
    addr_t robust_list;

    dword_t exit_code;
    _Bool zombie;
    _Bool exiting;

    struct vfork_info {
        _Bool done;
        cond_t cond;
        lock_t lock;
    } *vfork;
    int exit_signal;

    lock_t general_lock;

    struct task_sockrestart sockrestart;

    cond_t *waiting_cond;
    lock_t *waiting_lock;
    lock_t waiting_cond_lock;
};

extern __thread struct task *current;

static inline void task_set_mm(struct task *task, struct mm *mm)
{
    task->mm = mm;
    task->mem = task->cpu.mem = &task->mm->mem;
}

struct task * task_create_(struct task *parent);

void task_destroy(struct task *task);

void vfork_notify(struct task *task);
pid_t_ task_setsid(struct task *task);
void task_leave_session(struct task *task);

struct tgroup {
    struct list threads;
    struct task *leader;
    struct rusage_ rusage;

    pid_t_ sid, pgid;
    struct list session;
    struct list pgroup;

    _Bool stopped;
    cond_t stopped_cond;

    struct tty *tty;
    struct timer *timer;

    struct rlimit_ limits[16];

    _Bool doing_group_exit;
    dword_t group_exit_code;

    struct rusage_ children_rusage;
    cond_t child_exit;

    lock_t lock;
};

static inline _Bool task_is_leader(struct task *task)
{
    return task->group->leader == task;
}

struct pid {
    dword_t id;
    struct task *task;
    struct list session;
    struct list pgroup;
};

extern lock_t pids_lock;

struct pid * pid_get(dword_t pid);
struct task * pid_get_task(dword_t pid);
struct task * pid_get_task_zombie(dword_t id);

extern void (*task_run_hook)(void);

void task_start(struct task *task);

extern void (*exit_hook)(struct task *task, int code);
# 17 "/Users/bbarrows/repos/ish/jit/gen.c" 2

static void gen(struct gen_state *state, unsigned long thing)
{
    (__builtin_expect(!(state->size <= state->capacity), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish/jit/gen.c", 20, "state->size <= state->capacity") : (void)0);
    if (state->size >= state->capacity) {
        state->capacity *= 2;
        struct jit_block *bigger_block = realloc(state->block,
                                                 sizeof(struct jit_block) + state->capacity * sizeof(unsigned long));
        if (bigger_block == ((void *)0)) {
            die("out of memory while jitting");
        }
        state->block = bigger_block;
    }
    (__builtin_expect(!(state->size < state->capacity), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish/jit/gen.c", 30, "state->size < state->capacity") : (void)0);
    state->block->code[state->size++] = thing;
}

void gen_start(addr_t addr, struct gen_state *state)
{
    state->capacity = JIT_BLOCK_INITIAL_CAPACITY;
    state->size = 0;
    state->ip = addr;
    for (int i = 0; i <= 1; i++) {
        state->jump_ip[i] = 0;
    }
    state->block_patch_ip = 0;

    struct jit_block *block = malloc(sizeof(struct jit_block) + state->capacity * sizeof(unsigned long));
    state->block = block;
    block->addr = addr;
}

void gen_end(struct gen_state *state)
{
    struct jit_block *block = state->block;
    for (int i = 0; i <= 1; i++) {
        if (state->jump_ip[i] != 0) {
            block->jump_ip[i] = &block->code[state->jump_ip[i]];
            block->old_jump_ip[i] = *block->jump_ip[i];
        } else {
            block->jump_ip[i] = ((void *)0);
        }

        list_init(&block->jumps_from[i]);
        list_init(&block->jumps_from_links[i]);
    }
    if (state->block_patch_ip != 0) {
        block->code[state->block_patch_ip] = (unsigned long)block;
    }
    if (block->addr != state->ip) block->end_addr = state->ip - 1;
    else block->end_addr = block->addr;
    list_init(&block->chain);
    block->is_jetsam = 0;
    for (int i = 0; i <= 1; i++) {
        list_init(&block->page[i]);
    }
}

void gen_exit(struct gen_state *state)
{
    extern void gadget_exit(void);

    gen(state, (unsigned long)gadget_exit);
    gen(state, state->ip);
}

# 101 "/Users/bbarrows/repos/ish/jit/gen.c"
enum arg {
    arg_reg_a, arg_reg_c, arg_reg_d, arg_reg_b, arg_reg_sp, arg_reg_bp, arg_reg_si, arg_reg_di,
    arg_imm, arg_mem, arg_addr, arg_gs,
    arg_count, arg_invalid,

    arg_modrm_val, arg_modrm_reg,
    arg_xmm_modrm_val, arg_xmm_modrm_reg,
    arg_mem_addr, arg_1,
};

enum size {
    size_8, size_16, size_32,
    size_count,
    size_64, size_80, size_128,
};

enum cond {
    cond_O, cond_B, cond_E, cond_BE, cond_S, cond_P, cond_L, cond_LE,
    cond_count,
};

enum repeat {
    rep_once, rep_repz, rep_repnz,
    rep_count,
    rep_rep = rep_repz,
};

typedef void (*gadget_t)(void);
# 151 "/Users/bbarrows/repos/ish/jit/gen.c"
static inline int sz(int size)
{
    switch (size) {
        case 8: return size_8;
        case 16: return size_16;
        case 32: return size_32;
        default: return -1;
    }
}

_Bool gen_addr(struct gen_state *state, struct modrm *modrm, _Bool seg_gs, dword_t saved_ip)
{
    if (modrm->base == reg_none)
        do {
            do {
                extern void gadget_addr_none(void); gen(state, (unsigned long)(gadget_addr_none));
            } while (0); gen(state, (unsigned long)(modrm->offset));
        } while (0);
    else
        do {
            do {
                extern gadget_t addr_gadgets[]; if (addr_gadgets[modrm->base] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(addr_gadgets[modrm->base]));
            } while (0); gen(state, (unsigned long)(modrm->offset));
        } while (0);
    if (modrm->type == modrm_mem_si)
        do {
            extern gadget_t si_gadgets[]; if (si_gadgets[modrm->index * 4 + modrm->shift] == ((void *)0)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); gen(state, (unsigned long)(si_gadgets[modrm->index * 4 + modrm->shift]));
        } while (0);
    if (seg_gs)
        do {
            extern void gadget_seg_gs(void); gen(state, (unsigned long)(gadget_seg_gs));
        } while (0);
    return 1;
}

static inline _Bool gen_op(struct gen_state *state, gadget_t *gadgets, enum arg arg, struct modrm *modrm, uint64_t *imm, int size, dword_t saved_ip, _Bool seg_gs, dword_t addr_offset)
{
    size = sz(size);
    gadgets = gadgets + size * arg_count;

    switch (arg) {
        case arg_modrm_reg:

            arg = modrm->reg + arg_reg_a; break;
        case arg_modrm_val:
            if (modrm->type == modrm_reg) arg = modrm->base + arg_reg_a;
            else arg = arg_mem;
            break;
        case arg_mem_addr:
            arg = arg_mem;
            modrm->type = modrm_mem;
            modrm->base = reg_none;
            modrm->offset = addr_offset;
            break;
        case arg_1:
            arg = arg_imm;
            *imm = 1;
            break;
    }
    if (arg >= arg_count || gadgets[arg] == ((void *)0)) {
        do {
            do {
                do {
                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
            } while (0); return 0;
        } while (0);
    }
    if (arg == arg_mem || arg == arg_addr) {
        if (!gen_addr(state, modrm, seg_gs, saved_ip)) return 0;
    }
    gen(state, (unsigned long)(gadgets[arg]));
    if (arg == arg_imm) gen(state, (unsigned long)(*imm));
    else if (arg == arg_mem) gen(state, (unsigned long)(saved_ip));
    return 1;
}

# 356 "/Users/bbarrows/repos/ish/jit/gen.c"
void helper_rdtsc(struct cpu_state *cpu);
# 439 "/Users/bbarrows/repos/ish/jit/gen.c"
enum vec_arg {
    vec_arg_xmm, vec_arg_reg, vec_arg_imm, vec_arg_count,
    vec_arg_mem,
};

static inline enum vec_arg vecarg(enum arg arg, struct modrm *modrm)
{
    switch (arg) {
        case arg_modrm_reg:
            return vec_arg_reg;
        case arg_imm:
            return vec_arg_imm;
        case arg_xmm_modrm_reg:
            return vec_arg_xmm;
        case arg_modrm_val:
            if (modrm->type == modrm_reg) return vec_arg_reg;
            return vec_arg_mem;
        case arg_xmm_modrm_val:
            if (modrm->type == modrm_reg) return vec_arg_xmm;
            return vec_arg_mem;
        default:
            die("unimplemented vecarg");
    }
}

static inline _Bool gen_vec(enum arg rm, enum arg reg, void (*helper)(), gadget_t (*helper_gadgets_mem)[vec_arg_count], struct gen_state *state, struct modrm *modrm, uint8_t imm, dword_t saved_ip, _Bool seg_gs)
{
    enum vec_arg v_reg = vecarg(reg, modrm);
    enum vec_arg v_rm = vecarg(rm, modrm);

    gadget_t gadget;
    if (v_rm == vec_arg_mem) {
        gadget = (*helper_gadgets_mem)[v_reg];
    } else {
        extern gadget_t vec_helper_reg_gadgets[vec_arg_count][vec_arg_count];
        gadget = vec_helper_reg_gadgets[v_reg][v_rm];
    }
    if (gadget == ((void *)0)) {
        do {
            do {
                do {
                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
            } while (0); return 0;
        } while (0);
    }

    switch (v_rm) {
        case vec_arg_xmm:
            gen(state, (unsigned long)(gadget));
            gen(state, (unsigned long)(helper));
            gen(state, (unsigned long)((modrm->opcode * sizeof(union xmm_reg)) | (modrm->rm_opcode * sizeof(union xmm_reg) << 8)));

            break;

        case vec_arg_mem:
            gen_addr(state, modrm, seg_gs, saved_ip);
            gen(state, (unsigned long)(gadget));
            gen(state, (unsigned long)(saved_ip));
            gen(state, (unsigned long)(helper));
            gen(state, (unsigned long)(modrm->opcode * sizeof(union xmm_reg)));
            break;

        case vec_arg_imm:

            gen(state, (unsigned long)(gadget));
            gen(state, (unsigned long)(helper));
            gen(state, (unsigned long)((modrm->rm_opcode * sizeof(union xmm_reg)) | (((uint16_t)imm) << 8)));

            break;

        default: die("unimplemented vecarg");
    }
    return 1;
}

# 572 "/Users/bbarrows/repos/ish/jit/gen.c"
extern int current_pid(void);

__attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) int gen_step32(struct gen_state *state, struct tlb *tlb)
{
    dword_t saved_ip = state->ip; dword_t addr_offset = 0; _Bool end_block = 0; _Bool seg_gs = 0;

    byte_t insn;
    uint64_t imm = 0;
    struct modrm modrm;
# 590 "/Users/bbarrows/repos/ish/jit/gen.c"
 restart:
    __use(0, current_pid(), state->ip);
    if (!tlb_read(tlb, state->ip, &insn, 8 / 8)) do {
            do {
                do {
                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
            } while (0); return 0;
        } while (0); state->ip += 8 / 8; __use(0, insn);

    struct pt_entry *pe = mem_pt(current->mem, ((state->ip) >> 12));
    struct mem *mem = current->mem;

    printk("\nip is %x\n", state->ip);
    printk("INTERP: Just read op %x\n", insn);
    printk("\n Page table for ip %x    address offset  %x \n", ((state->ip) >> 12), ((state->ip) & ((1 << 12) - 1)));
    if (pe && pe->data) {
        struct data *d = pe->data;
        printk("\n memory offset:  %x   file offset: %x %x \n", pe->offset, d->file_offset);

        printk("\n ip in group of pages   start %x   num pages  %x    dbgstr   %s  \n", d->pgstart, d->pgnum, d->debugString);
    }

    switch (insn) {
# 632 "/Users/bbarrows/repos/ish/jit/gen.c"
        case 0x00 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x00 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x00 + 0x2: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x00 + 0x3: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x00 + 0x4: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x00 + 0x5: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x08 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x08 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x08 + 0x2: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x08 + 0x3: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x08 + 0x4: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x08 + 0x5: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;

        case 0x0f:

            if (!tlb_read(tlb, state->ip, &insn, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, insn);
            switch (insn) {
                case 0x18 ... 0x1f: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); break;

                case 0x28: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t vec_helper_load128_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_load128, &vec_helper_load128_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                    } while (0); break;
                case 0x29: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t vec_helper_store128_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_store128, &vec_helper_store128_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                    } while (0); break;

                case 0x2e: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t vec_helper_load32_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_compare32, &vec_helper_load32_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                    } while (0);
                    break;

                case 0x31: __use(0);
                    do {
                        do {
                            extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                        } while (0); gen(state, (unsigned long)(helper_rdtsc));
                    } while (0); break;

                case 0x40: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skipn_gadgets[]; if (skipn_gadgets[cond_O] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skipn_gadgets[cond_O]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x41: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skip_gadgets[]; if (skip_gadgets[cond_O] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skip_gadgets[cond_O]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x42: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skipn_gadgets[]; if (skipn_gadgets[cond_B] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skipn_gadgets[cond_B]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x43: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skip_gadgets[]; if (skip_gadgets[cond_B] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skip_gadgets[cond_B]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x44: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skipn_gadgets[]; if (skipn_gadgets[cond_E] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skipn_gadgets[cond_E]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x45: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skip_gadgets[]; if (skip_gadgets[cond_E] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skip_gadgets[cond_E]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x46: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skipn_gadgets[]; if (skipn_gadgets[cond_BE] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skipn_gadgets[cond_BE]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x47: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skip_gadgets[]; if (skip_gadgets[cond_BE] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skip_gadgets[cond_BE]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x48: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skipn_gadgets[]; if (skipn_gadgets[cond_S] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skipn_gadgets[cond_S]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x49: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skip_gadgets[]; if (skip_gadgets[cond_S] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skip_gadgets[cond_S]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x4a: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skipn_gadgets[]; if (skipn_gadgets[cond_P] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skipn_gadgets[cond_P]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x4b: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skip_gadgets[]; if (skip_gadgets[cond_P] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skip_gadgets[cond_P]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x4c: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skipn_gadgets[]; if (skipn_gadgets[cond_L] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skipn_gadgets[cond_L]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x4d: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skip_gadgets[]; if (skip_gadgets[cond_L] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skip_gadgets[cond_L]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x4e: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skipn_gadgets[]; if (skipn_gadgets[cond_LE] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skipn_gadgets[cond_LE]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;
                case 0x4f: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        do {
                            do {
                                extern gadget_t skip_gadgets[]; if (skip_gadgets[cond_LE] == ((void *)0)) do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); gen(state, (unsigned long)(skip_gadgets[cond_LE]));
                            } while (0); gen(state, (unsigned long)(0));
                        } while (0); int start = state->size; do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); state->block->code[start - 1] = (state->size - start) * sizeof(long);
                    } while (0); break;

                case 0x57: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t vec_helper_load128_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_xor128, &vec_helper_load128_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                    } while (0);
                    break;

                case 0x6e: __use(0);

                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t vec_helper_load32_gadgets[vec_arg_count]; if (!gen_vec(arg_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_zload32, &vec_helper_load32_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                    } while (0);
                    break;

                case 0x6f: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t vec_helper_load128_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_load128, &vec_helper_load128_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                    } while (0); break;

                case 0x73: if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0);
                    switch (modrm.opcode) {
                        case 0x02: __use(0);
                            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                                extern gadget_t vec_helper_load64_gadgets[vec_arg_count]; if (!gen_vec(arg_imm, arg_xmm_modrm_val, (void (*)())vec_imm_shiftr64, &vec_helper_load64_gadgets, state, &modrm, imm, saved_ip, seg_gs)) return 0;
                            } while (0); break;
                        default: do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;

                case 0x77: __use(0); break;

                case 0x7e: __use(0);

                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t vec_helper_store32_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_store32, &vec_helper_store32_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                    } while (0);
                    break;

                case 0x7f: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t vec_helper_store128_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_store128, &vec_helper_store128_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                    } while (0); break;

                case 0x80: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_O] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_O]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x81: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_O] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_O]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x82: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_B] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_B]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x83: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_B] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_B]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x84: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_E] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_E]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x85: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_E] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_E]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x86: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_BE] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_BE]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x87: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_BE] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_BE]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x88: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_S] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_S]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x89: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_S] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_S]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x8a: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_P] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_P]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x8b: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_P] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_P]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x8c: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_L] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_L]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x8d: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_L] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_L]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x8e: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_LE] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_LE]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
                case 0x8f: __use(0);
                    if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        do {
                            extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_LE] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_LE]));
                        } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                    } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;

                case 0x90: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t set_gadgets[]; if (set_gadgets[cond_O] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(set_gadgets[cond_O]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x91: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t setn_gadgets[]; if (setn_gadgets[cond_O] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(setn_gadgets[cond_O]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x92: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t set_gadgets[]; if (set_gadgets[cond_B] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(set_gadgets[cond_B]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x93: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t setn_gadgets[]; if (setn_gadgets[cond_B] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(setn_gadgets[cond_B]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x94: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t set_gadgets[]; if (set_gadgets[cond_E] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(set_gadgets[cond_E]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x95: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t setn_gadgets[]; if (setn_gadgets[cond_E] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(setn_gadgets[cond_E]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x96: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t set_gadgets[]; if (set_gadgets[cond_BE] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(set_gadgets[cond_BE]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x97: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t setn_gadgets[]; if (setn_gadgets[cond_BE] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(setn_gadgets[cond_BE]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x98: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t set_gadgets[]; if (set_gadgets[cond_S] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(set_gadgets[cond_S]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x99: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t setn_gadgets[]; if (setn_gadgets[cond_S] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(setn_gadgets[cond_S]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x9a: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t set_gadgets[]; if (set_gadgets[cond_P] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(set_gadgets[cond_P]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x9b: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t setn_gadgets[]; if (setn_gadgets[cond_P] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(setn_gadgets[cond_P]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x9c: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t set_gadgets[]; if (set_gadgets[cond_L] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(set_gadgets[cond_L]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x9d: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t setn_gadgets[]; if (setn_gadgets[cond_L] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(setn_gadgets[cond_L]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x9e: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t set_gadgets[]; if (set_gadgets[cond_LE] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(set_gadgets[cond_LE]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0x9f: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t setn_gadgets[]; if (setn_gadgets[cond_LE] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(setn_gadgets[cond_LE]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xa2: __use(0); do {
                        extern void gadget_cpuid(void); gen(state, (unsigned long)(gadget_cpuid));
                } while (0); break;

                case 0xa3: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t bt_gadgets[]; if (!gen_op(state, bt_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xa4: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); if (arg_imm == arg_reg_c) do {
                            extern gadget_t shld_cl_gadgets[]; if (!gen_op(state, shld_cl_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); else {
                        do {
                            extern gadget_t shld_imm_gadgets[]; if (!gen_op(state, shld_imm_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); gen(state, (unsigned long)(imm));
                    } do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0xa5: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); if (arg_reg_c == arg_reg_c) do {
                            extern gadget_t shld_cl_gadgets[]; if (!gen_op(state, shld_cl_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); else {
                        do {
                            extern gadget_t shld_imm_gadgets[]; if (!gen_op(state, shld_imm_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); gen(state, (unsigned long)(imm));
                    } do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xab: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t bts_gadgets[]; if (!gen_op(state, bts_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xac: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); if (arg_imm == arg_reg_c) do {
                            extern gadget_t shrd_cl_gadgets[]; if (!gen_op(state, shrd_cl_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); else {
                        do {
                            extern gadget_t shrd_imm_gadgets[]; if (!gen_op(state, shrd_imm_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); gen(state, (unsigned long)(imm));
                    } do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0xad: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); if (arg_reg_c == arg_reg_c) do {
                            extern gadget_t shrd_cl_gadgets[]; if (!gen_op(state, shrd_cl_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); else {
                        do {
                            extern gadget_t shrd_imm_gadgets[]; if (!gen_op(state, shrd_imm_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); gen(state, (unsigned long)(imm));
                    } do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xaf: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t imul_gadgets[]; if (!gen_op(state, imul_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xb0: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t cmpxchg_gadgets[]; if (!gen_op(state, cmpxchg_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0xb1: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t cmpxchg_gadgets[]; if (!gen_op(state, cmpxchg_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xb3: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t btr_gadgets[]; if (!gen_op(state, btr_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xb6: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t zero_extend_gadgets[]; if (zero_extend_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(zero_extend_gadgets[sz(8)]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0xb7: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 16, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t zero_extend_gadgets[]; if (zero_extend_gadgets[sz(16)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(zero_extend_gadgets[sz(16)]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
# 825 "/Users/bbarrows/repos/ish/jit/gen.c"
                case 0xba: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; switch (modrm.opcode) {
                        case 4: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t bt_gadgets[]; if (!gen_op(state, bt_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 5: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t bts_gadgets[]; if (!gen_op(state, bts_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 6: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t btr_gadgets[]; if (!gen_op(state, btr_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 7: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t btc_gadgets[]; if (!gen_op(state, btc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; default: do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;

                case 0xbb: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t btc_gadgets[]; if (!gen_op(state, btc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0xbc: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t bsf_gadgets[]; if (!gen_op(state, bsf_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0xbd: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t bsr_gadgets[]; if (!gen_op(state, bsr_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xbe: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t sign_extend_gadgets[]; if (sign_extend_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(sign_extend_gadgets[sz(8)]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0xbf: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 16, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t sign_extend_gadgets[]; if (sign_extend_gadgets[sz(16)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(sign_extend_gadgets[sz(16)]));
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xc0: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;
                case 0xc1: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                    } while (0); break;

                case 0xc7: if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); switch (modrm.opcode) {
                        case 1: __use(0);
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_cmpxchg8b(void); gen(state, (unsigned long)(gadget_cmpxchg8b));
                                } while (0); gen(state, (unsigned long)(saved_ip));
                            } while (0); break;
                        default: do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                }

                case 0xc8: __use(0);
                    do {
                        extern gadget_t bswap_gadgets[]; if (bswap_gadgets[arg_reg_a] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(bswap_gadgets[arg_reg_a]));
                    } while (0); break;
                case 0xc9: __use(0);
                    do {
                        extern gadget_t bswap_gadgets[]; if (bswap_gadgets[arg_reg_c] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(bswap_gadgets[arg_reg_c]));
                    } while (0); break;
                case 0xca: __use(0);
                    do {
                        extern gadget_t bswap_gadgets[]; if (bswap_gadgets[arg_reg_d] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(bswap_gadgets[arg_reg_d]));
                    } while (0); break;
                case 0xcb: __use(0);
                    do {
                        extern gadget_t bswap_gadgets[]; if (bswap_gadgets[arg_reg_b] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(bswap_gadgets[arg_reg_b]));
                    } while (0); break;
                case 0xcc: __use(0);
                    do {
                        extern gadget_t bswap_gadgets[]; if (bswap_gadgets[arg_reg_sp] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(bswap_gadgets[arg_reg_sp]));
                    } while (0); break;
                case 0xcd: __use(0);
                    do {
                        extern gadget_t bswap_gadgets[]; if (bswap_gadgets[arg_reg_bp] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(bswap_gadgets[arg_reg_bp]));
                    } while (0); break;
                case 0xce: __use(0);
                    do {
                        extern gadget_t bswap_gadgets[]; if (bswap_gadgets[arg_reg_si] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(bswap_gadgets[arg_reg_si]));
                    } while (0); break;
                case 0xcf: __use(0);
                    do {
                        extern gadget_t bswap_gadgets[]; if (bswap_gadgets[arg_reg_di] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(bswap_gadgets[arg_reg_di]));
                    } while (0); break;
# 878 "/Users/bbarrows/repos/ish/jit/gen.c"
                default: __use(0);
                    do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0);
            }
            break;

        case 0x10 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x10 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x10 + 0x2: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x10 + 0x3: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x10 + 0x4: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x10 + 0x5: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x18 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x18 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x18 + 0x2: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x18 + 0x3: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x18 + 0x4: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x18 + 0x5: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x20 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x20 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x20 + 0x2: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x20 + 0x3: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x20 + 0x4: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x20 + 0x5: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x28 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x28 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x28 + 0x2: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x28 + 0x3: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x28 + 0x4: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x28 + 0x5: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;

        case 0x2e: __use(0); goto restart;

        case 0x30 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x30 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x30 + 0x2: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x30 + 0x3: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x30 + 0x4: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x30 + 0x5: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x38 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x38 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x38 + 0x2: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x38 + 0x3: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x38 + 0x4: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break; case 0x38 + 0x5: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;

        case 0x3e: __use(0); goto restart;

        case 0x40: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x41: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x42: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x43: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x44: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x45: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x46: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x47: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x48: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x49: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x4a: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x4b: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x4c: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x4d: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x4e: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x4f: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;

        case 0x50: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0x51: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0x52: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0x53: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0x54: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0x55: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0x56: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0x57: __use(0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;

        case 0x58: __use(0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x59: __use(0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x5a: __use(0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x5b: __use(0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x5c: __use(0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x5d: __use(0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x5e: __use(0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;
        case 0x5f: __use(0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
        } while (0); break;

        case 0x65: __use(0); seg_gs = 1; goto restart;

        case 0x60: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0);
            break;
        case 0x61: __use(0);
            do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0);

            do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0);
            do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0);
            do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0);
            break;

        case 0x66:

            __use(0);

        case 0x67: __use(0); goto restart;

        case 0x68: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); break;
        case 0x69: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t imul_gadgets[]; if (!gen_op(state, imul_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x6a: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); break;
        case 0x6b: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t imul_gadgets[]; if (!gen_op(state, imul_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0x70: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_O] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_O]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x71: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_O] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_O]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x72: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_B] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_B]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x73: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_B] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_B]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x74: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_E] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_E]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x75: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_E] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_E]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x76: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_BE] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_BE]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x77: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_BE] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_BE]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x78: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_S] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_S]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x79: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_S] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_S]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x7a: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_P] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_P]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x7b: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_P] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_P]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x7c: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_L] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_L]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x7d: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_L] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_L]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x7e: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_LE] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_LE]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
        case 0x7f: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern gadget_t jmp_gadgets[]; if (jmp_gadgets[cond_LE] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(jmp_gadgets[cond_LE]));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;
# 1021 "/Users/bbarrows/repos/ish/jit/gen.c"
        case 0x80: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; default: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;
        case 0x81: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; default: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;
        case 0x83: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t add_gadgets[]; if (!gen_op(state, add_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t or_gadgets[]; if (!gen_op(state, or_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t adc_gadgets[]; if (!gen_op(state, adc_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sbb_gadgets[]; if (!gen_op(state, sbb_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t xor_gadgets[]; if (!gen_op(state, xor_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; default: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;

        case 0x84: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x85: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0x86: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x87: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0x88: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x89: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x8a: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x8b: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0x8d: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (modrm.type == modrm_reg) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_addr, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0x8c: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0);
            if (modrm.reg != reg_ebp) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_gs, &modrm, &imm, 16, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 16, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x8e: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0);
            if (modrm.reg != reg_ebp) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 16, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_gs, &modrm, &imm, 16, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0x8f: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0x90: __use(0); break;
        case 0x91: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x92: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x93: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x94: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x95: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x96: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0x97: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t xchg_gadgets[]; if (!gen_op(state, xchg_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0x98: __use(0); do {
                extern gadget_t cvte_gadgets[]; if (cvte_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(cvte_gadgets[sz(32)]));
        } while (0); break;
        case 0x99: __use(0); do {
                extern gadget_t cvt_gadgets[]; if (cvt_gadgets[sz(32)] == ((void *)0)) do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                    } while (0); gen(state, (unsigned long)(cvt_gadgets[sz(32)]));
        } while (0); break;

        case 0x9b: __use(0); break;

        case 0x9c: __use(0); do {
                extern void gadget_pushf(void); gen(state, (unsigned long)(gadget_pushf));
        } while (0); break;
        case 0x9d: __use(0); do {
                extern void gadget_popf(void); gen(state, (unsigned long)(gadget_popf));
        } while (0); break;
        case 0x9e: __use(0); do {
                extern void gadget_sahf(void); gen(state, (unsigned long)(gadget_sahf));
        } while (0); break;

        case 0xa0: __use(0);
            if (!tlb_read(tlb, state->ip, &addr_offset, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_mem_addr, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xa1: __use(0);
            if (!tlb_read(tlb, state->ip, &addr_offset, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_mem_addr, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xa2: __use(0);
            if (!tlb_read(tlb, state->ip, &addr_offset, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_mem_addr, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xa3: __use(0);
            if (!tlb_read(tlb, state->ip, &addr_offset, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_mem_addr, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0xa4: __use(0); do {
                do {
                    extern gadget_t movs_gadgets[]; if (movs_gadgets[sz(8) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(movs_gadgets[sz(8) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0xa5: __use(0); do {
                do {
                    extern gadget_t movs_gadgets[]; if (movs_gadgets[sz(32) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(movs_gadgets[sz(32) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0xa6: __use(0); do {
                do {
                    extern gadget_t cmps_gadgets[]; if (cmps_gadgets[sz(8) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(cmps_gadgets[sz(8) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0xa7: __use(0); do {
                do {
                    extern gadget_t cmps_gadgets[]; if (cmps_gadgets[sz(32) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(cmps_gadgets[sz(32) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;

        case 0xa8: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xa9: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0xaa: __use(0); do {
                do {
                    extern gadget_t stos_gadgets[]; if (stos_gadgets[sz(8) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(stos_gadgets[sz(8) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0xab: __use(0); do {
                do {
                    extern gadget_t stos_gadgets[]; if (stos_gadgets[sz(32) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(stos_gadgets[sz(32) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0xac: __use(0); do {
                do {
                    extern gadget_t lods_gadgets[]; if (lods_gadgets[sz(8) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(lods_gadgets[sz(8) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0xad: __use(0); do {
                do {
                    extern gadget_t lods_gadgets[]; if (lods_gadgets[sz(32) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(lods_gadgets[sz(32) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0xae: __use(0); do {
                do {
                    extern gadget_t scas_gadgets[]; if (scas_gadgets[sz(8) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(scas_gadgets[sz(8) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;
        case 0xaf: __use(0); do {
                do {
                    extern gadget_t scas_gadgets[]; if (scas_gadgets[sz(32) * size_count + rep_once] == ((void *)0)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); gen(state, (unsigned long)(scas_gadgets[sz(32) * size_count + rep_once]));
                } while (0); gen(state, (unsigned long)(saved_ip));
        } while (0); break;

        case 0xb0: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xb1: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_c, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xb2: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_d, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xb3: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_b, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xb4: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_sp, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xb5: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_bp, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xb6: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_si, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xb7: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_di, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0xb8: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_a, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xb9: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xba: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_d, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xbb: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_b, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xbc: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xbd: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xbe: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_si, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xbf: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_di, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
# 1161 "/Users/bbarrows/repos/ish/jit/gen.c"
        case 0xc0: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rol_gadgets[]; if (!gen_op(state, rol_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t ror_gadgets[]; if (!gen_op(state, ror_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcl_gadgets[]; if (!gen_op(state, rcl_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcr_gadgets[]; if (!gen_op(state, rcr_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shl_gadgets[]; if (!gen_op(state, shl_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shr_gadgets[]; if (!gen_op(state, shr_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sar_gadgets[]; if (!gen_op(state, sar_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
            }
            break;
        case 0xc1: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rol_gadgets[]; if (!gen_op(state, rol_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t ror_gadgets[]; if (!gen_op(state, ror_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcl_gadgets[]; if (!gen_op(state, rcl_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcr_gadgets[]; if (!gen_op(state, rcr_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shl_gadgets[]; if (!gen_op(state, shl_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shr_gadgets[]; if (!gen_op(state, shr_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sar_gadgets[]; if (!gen_op(state, sar_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
            }
            break;

        case 0xc2: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 16 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 16 / 8; __use(0, (long long)imm); do {
                do {
                    extern void gadget_ret(void); gen(state, (unsigned long)(gadget_ret));
                } while (0); gen(state, (unsigned long)(saved_ip)); gen(state, (unsigned long)(4 + imm));
            } while (0); end_block = 1; break;
        case 0xc3: __use(0);
            do {
                do {
                    extern void gadget_ret(void); gen(state, (unsigned long)(gadget_ret));
                } while (0); gen(state, (unsigned long)(saved_ip)); gen(state, (unsigned long)(4 + 0));
            } while (0); end_block = 1; break;

        case 0xc9: __use(0);
            do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_sp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                do {
                    extern void gadget_pop(void); gen(state, (unsigned long)(gadget_pop));
                } while (0); gen(state, (unsigned long)(saved_ip));
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_reg_bp, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0xcd: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                } while (0); gen(state, (unsigned long)((uint8_t)imm)); gen(state, (unsigned long)(state->ip));
            } while (0); end_block = 1; break;

        case 0xc6: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;
        case 0xc7: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); do {
                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
            } while (0); break;

        case 0xd0: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rol_gadgets[]; if (!gen_op(state, rol_gadgets, arg_1, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t ror_gadgets[]; if (!gen_op(state, ror_gadgets, arg_1, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcl_gadgets[]; if (!gen_op(state, rcl_gadgets, arg_1, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcr_gadgets[]; if (!gen_op(state, rcr_gadgets, arg_1, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shl_gadgets[]; if (!gen_op(state, shl_gadgets, arg_1, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shr_gadgets[]; if (!gen_op(state, shr_gadgets, arg_1, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sar_gadgets[]; if (!gen_op(state, sar_gadgets, arg_1, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
            }
            break;
        case 0xd1: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rol_gadgets[]; if (!gen_op(state, rol_gadgets, arg_1, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t ror_gadgets[]; if (!gen_op(state, ror_gadgets, arg_1, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcl_gadgets[]; if (!gen_op(state, rcl_gadgets, arg_1, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcr_gadgets[]; if (!gen_op(state, rcr_gadgets, arg_1, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shl_gadgets[]; if (!gen_op(state, shl_gadgets, arg_1, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shr_gadgets[]; if (!gen_op(state, shr_gadgets, arg_1, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sar_gadgets[]; if (!gen_op(state, sar_gadgets, arg_1, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
            }
            break;
        case 0xd2: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rol_gadgets[]; if (!gen_op(state, rol_gadgets, arg_reg_c, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t ror_gadgets[]; if (!gen_op(state, ror_gadgets, arg_reg_c, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcl_gadgets[]; if (!gen_op(state, rcl_gadgets, arg_reg_c, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcr_gadgets[]; if (!gen_op(state, rcr_gadgets, arg_reg_c, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shl_gadgets[]; if (!gen_op(state, shl_gadgets, arg_reg_c, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shr_gadgets[]; if (!gen_op(state, shr_gadgets, arg_reg_c, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sar_gadgets[]; if (!gen_op(state, sar_gadgets, arg_reg_c, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
            }
            break;
        case 0xd3: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rol_gadgets[]; if (!gen_op(state, rol_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t ror_gadgets[]; if (!gen_op(state, ror_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcl_gadgets[]; if (!gen_op(state, rcl_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t rcr_gadgets[]; if (!gen_op(state, rcr_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shl_gadgets[]; if (!gen_op(state, shl_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t shr_gadgets[]; if (!gen_op(state, shr_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sar_gadgets[]; if (!gen_op(state, sar_gadgets, arg_reg_c, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
            }
            break;

        case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd: case 0xde: case 0xdf:
            __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0);
            if (modrm.type != modrm_reg) {
                switch (insn << 4 | modrm.opcode) {
                    case 0xd80: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_addm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd81: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_mulm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd82: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_comm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd83: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_comm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xd84: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_subm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd85: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_subrm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd86: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_divm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd87: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_divrm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd90: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_ldm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd92: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write32(void); gen(state, (unsigned long)(gadget_helper_write32));
                                } while (0); gen(state, (unsigned long)(fpu_stm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xd93: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write32(void); gen(state, (unsigned long)(gadget_helper_write32));
                                } while (0); gen(state, (unsigned long)(fpu_stm32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;

                    case 0xd94: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write32(void); gen(state, (unsigned long)(gadget_helper_write32));
                                } while (0); gen(state, (unsigned long)(fpu_ldenv32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;

                    case 0xd95: __use(0); if (arg_mem_addr == arg_reg_a) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); else do {
                                gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                    do {
                                        extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                    } while (0); gen(state, (unsigned long)(fpu_ldcw16)); gen(state, (unsigned long)(saved_ip));
                                } while (0);
                            } while (0); break;

                    case 0xd96: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write32(void); gen(state, (unsigned long)(gadget_helper_write32));
                                } while (0); gen(state, (unsigned long)(fpu_stenv32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;

                    case 0xd97: __use(0); if (arg_mem_addr == arg_reg_a) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); else do {
                                gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                    do {
                                        extern void gadget_helper_write16(void); gen(state, (unsigned long)(gadget_helper_write16));
                                    } while (0); gen(state, (unsigned long)(fpu_stcw16)); gen(state, (unsigned long)(saved_ip));
                                } while (0);
                            } while (0); break;
                    case 0xda0: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_iadd32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xda1: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_imul32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xda2: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_icom32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xda3: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_icom32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xda4: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_isub32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xda5: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_isubr32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xda6: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_idiv32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xda7: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_idivr32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdb0: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read32(void); gen(state, (unsigned long)(gadget_helper_read32));
                                } while (0); gen(state, (unsigned long)(fpu_ild32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdb2: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write32(void); gen(state, (unsigned long)(gadget_helper_write32));
                                } while (0); gen(state, (unsigned long)(fpu_ist32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdb3: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write32(void); gen(state, (unsigned long)(gadget_helper_write32));
                                } while (0); gen(state, (unsigned long)(fpu_ist32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdb5: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read80(void); gen(state, (unsigned long)(gadget_helper_read80));
                                } while (0); gen(state, (unsigned long)(fpu_ldm80)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdb7: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write80(void); gen(state, (unsigned long)(gadget_helper_write80));
                                } while (0); gen(state, (unsigned long)(fpu_stm80)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdc0: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_addm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdc1: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_mulm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdc2: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_comm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdc3: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_comm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdc4: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_subm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdc5: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_subrm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdc6: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_divm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdc7: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_divrm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdd0: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_ldm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdd2: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write64(void); gen(state, (unsigned long)(gadget_helper_write64));
                                } while (0); gen(state, (unsigned long)(fpu_stm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdd3: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write64(void); gen(state, (unsigned long)(gadget_helper_write64));
                                } while (0); gen(state, (unsigned long)(fpu_stm64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdd4: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write32(void); gen(state, (unsigned long)(gadget_helper_write32));
                                } while (0); gen(state, (unsigned long)(fpu_restore32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdd6: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write32(void); gen(state, (unsigned long)(gadget_helper_write32));
                                } while (0); gen(state, (unsigned long)(fpu_save32)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xde0: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_iadd16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xde1: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_imul16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xde2: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_icom16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xde3: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_icom16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xde4: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_isub16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xde5: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_isubr16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xde6: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_idiv16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xde7: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_idivr16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdf0: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read16(void); gen(state, (unsigned long)(gadget_helper_read16));
                                } while (0); gen(state, (unsigned long)(fpu_ild16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdf2: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write16(void); gen(state, (unsigned long)(gadget_helper_write16));
                                } while (0); gen(state, (unsigned long)(fpu_ist16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdf3: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write16(void); gen(state, (unsigned long)(gadget_helper_write16));
                                } while (0); gen(state, (unsigned long)(fpu_ist16)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdf5: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_read64(void); gen(state, (unsigned long)(gadget_helper_read64));
                                } while (0); gen(state, (unsigned long)(fpu_ild64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); break;
                    case 0xdf7: __use(0); do {
                            gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                do {
                                    extern void gadget_helper_write64(void); gen(state, (unsigned long)(gadget_helper_write64));
                                } while (0); gen(state, (unsigned long)(fpu_ist64)); gen(state, (unsigned long)(saved_ip));
                            } while (0);
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    default: __use(0); do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                    } while (0);
                }
            } else {
                switch (insn << 4 | modrm.opcode) {
                    case 0xd80: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_add)); gen(state, (unsigned long)(modrm.rm_opcode)); gen(state, (unsigned long)(0));
                    } while (0); break;
                    case 0xd81: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_mul)); gen(state, (unsigned long)(modrm.rm_opcode)); gen(state, (unsigned long)(0));
                    } while (0); break;
                    case 0xd82: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_com)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xd83: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_com)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xd84: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_sub)); gen(state, (unsigned long)(modrm.rm_opcode)); gen(state, (unsigned long)(0));
                    } while (0); break;
                    case 0xd85: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_subr)); gen(state, (unsigned long)(modrm.rm_opcode)); gen(state, (unsigned long)(0));
                    } while (0); break;
                    case 0xd86: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_div)); gen(state, (unsigned long)(modrm.rm_opcode)); gen(state, (unsigned long)(0));
                    } while (0); break;
                    case 0xd87: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_divr)); gen(state, (unsigned long)(modrm.rm_opcode)); gen(state, (unsigned long)(0));
                    } while (0); break;
                    case 0xd90: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_ld)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0);  break;
                    case 0xd91: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_xch)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdb5: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_comi)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdb6: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_comi)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdc0: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_add)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdc1: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_mul)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdc4: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_subr)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdc5: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_sub)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdc6: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_divr)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdc7: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_div)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdd0: __use(0); break;
                    case 0xdd3: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_st)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdd4: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_com)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); break;
                    case 0xdd5: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_com)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xda5: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_com)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xde0: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_add)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xde1: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_mul)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xde4: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_subr)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xde5: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_sub)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xde6: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_divr)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xde7: __use(0); do {
                            do {
                                extern void gadget_helper_2(void); gen(state, (unsigned long)(gadget_helper_2));
                            } while (0); gen(state, (unsigned long)(fpu_div)); gen(state, (unsigned long)(0)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdf0: __use(0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdf5: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_comi)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    case 0xdf6: __use(0); do {
                            do {
                                extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                            } while (0); gen(state, (unsigned long)(fpu_comi)); gen(state, (unsigned long)(modrm.rm_opcode));
                    } while (0); do {
                            do {
                                extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                            } while (0); gen(state, (unsigned long)(fpu_pop));
                    } while (0); break;
                    default: switch (insn << 8 | modrm.opcode << 4 | modrm.rm_opcode) {
                            case 0xd940: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_chs));
                            } while (0); break;
                            case 0xd941: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_abs));
                            } while (0); break;
                            case 0xd944: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_tst));
                            } while (0); break;
                            case 0xd945: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_xam));
                            } while (0); break;
                            case 0xd950: __use(0); do {
                                    do {
                                        extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                                    } while (0); gen(state, (unsigned long)(fpu_ldc)); gen(state, (unsigned long)(fconst_one));
                            } while (0); break;
                            case 0xd951: __use(0); do {
                                    do {
                                        extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                                    } while (0); gen(state, (unsigned long)(fpu_ldc)); gen(state, (unsigned long)(fconst_log2t));
                            } while (0); break;
                            case 0xd952: __use(0); do {
                                    do {
                                        extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                                    } while (0); gen(state, (unsigned long)(fpu_ldc)); gen(state, (unsigned long)(fconst_log2e));
                            } while (0); break;
                            case 0xd953: __use(0); do {
                                    do {
                                        extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                                    } while (0); gen(state, (unsigned long)(fpu_ldc)); gen(state, (unsigned long)(fconst_pi));
                            } while (0); break;
                            case 0xd954: __use(0); do {
                                    do {
                                        extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                                    } while (0); gen(state, (unsigned long)(fpu_ldc)); gen(state, (unsigned long)(fconst_log2));
                            } while (0); break;
                            case 0xd955: __use(0); do {
                                    do {
                                        extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                                    } while (0); gen(state, (unsigned long)(fpu_ldc)); gen(state, (unsigned long)(fconst_ln2));
                            } while (0); break;
                            case 0xd956: __use(0); do {
                                    do {
                                        extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                                    } while (0); gen(state, (unsigned long)(fpu_ldc)); gen(state, (unsigned long)(fconst_zero));
                            } while (0); break;
                            case 0xd960: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_2xm1));
                            } while (0); break;
                            case 0xd961: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_yl2x));
                            } while (0); break;
                            case 0xd963: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_patan));
                            } while (0); break;
                            case 0xd967: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_incstp));
                            } while (0); break;
                            case 0xd970: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_prem));
                            } while (0); break;
                            case 0xd972: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_sqrt));
                            } while (0); break;
                            case 0xd974: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_rndint));
                            } while (0); break;
                            case 0xd975: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_scale));
                            } while (0); break;
                            case 0xd976: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_sin));
                            } while (0); break;
                            case 0xd977: __use(0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_cos));
                            } while (0); break;
                            case 0xde31: __use(0); do {
                                    do {
                                        extern void gadget_helper_1(void); gen(state, (unsigned long)(gadget_helper_1));
                                    } while (0); gen(state, (unsigned long)(fpu_com)); gen(state, (unsigned long)(modrm.rm_opcode));
                            } while (0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_pop));
                            } while (0); do {
                                    do {
                                        extern void gadget_helper_0(void); gen(state, (unsigned long)(gadget_helper_0));
                                    } while (0); gen(state, (unsigned long)(fpu_pop));
                            } while (0); break;
                            case 0xdf40: __use(0); if (arg_reg_a == arg_reg_a) do {
                                        extern void gadget_fstsw_ax(void); gen(state, (unsigned long)(gadget_fstsw_ax));
                                    } while (0); else do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                    } while (0); break;
                            default: __use(0); do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                            } while (0);
                    }
                }
            }
            break;

        case 0xe3: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern void gadget_jcxz(void); gen(state, (unsigned long)(gadget_jcxz));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm)); gen(state, (unsigned long)((state->ip | (1ul << 63))));
            } while (0); state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1; break;

        case 0xe8: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                do {
                    do {
                        extern void gadget_call(void); gen(state, (unsigned long)(gadget_call));
                    } while (0); gen(state, (unsigned long)(saved_ip)); gen(state, (unsigned long)(-1)); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
                } while (0); state->block_patch_ip = state->size - 4; state->jump_ip[0] = state->size + -2; if (-1 != 0) state->jump_ip[1] = state->size + -1; end_block = 1;
            } while (0); break;

        case 0xe9: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                do {
                    extern void gadget_jmp(void); gen(state, (unsigned long)(gadget_jmp));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -1; if (0 != 0) state->jump_ip[1] = state->size + 0; end_block = 1; break;
        case 0xeb: __use(0);
            if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                do {
                    extern void gadget_jmp(void); gen(state, (unsigned long)(gadget_jmp));
                } while (0); gen(state, (unsigned long)((state->ip | (1ul << 63)) + imm));
            } while (0); state->jump_ip[0] = state->size + -1; if (0 != 0) state->jump_ip[1] = state->size + 0; end_block = 1; break;

        case 0xf0:
 lockrestart:
            if (!tlb_read(tlb, state->ip, &insn, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, insn);
            switch (insn) {
                case 0x65: __use(0); seg_gs = 1; goto lockrestart;

                case 0x66:

                    __use(0);
                    state->ip = saved_ip;
# 1356 "/Users/bbarrows/repos/ish/jit/gen.c"
                case 0x00 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_add_gadgets[]; if (!gen_op(state, atomic_add_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 0x00 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_add_gadgets[]; if (!gen_op(state, atomic_add_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
                case 0x08 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_or_gadgets[]; if (!gen_op(state, atomic_or_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 0x08 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_or_gadgets[]; if (!gen_op(state, atomic_or_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
                case 0x10 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_adc_gadgets[]; if (!gen_op(state, atomic_adc_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 0x10 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_adc_gadgets[]; if (!gen_op(state, atomic_adc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
                case 0x18 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_sbb_gadgets[]; if (!gen_op(state, atomic_sbb_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 0x18 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_sbb_gadgets[]; if (!gen_op(state, atomic_sbb_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
                case 0x20 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_and_gadgets[]; if (!gen_op(state, atomic_and_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 0x20 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_and_gadgets[]; if (!gen_op(state, atomic_and_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
                case 0x28 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_sub_gadgets[]; if (!gen_op(state, atomic_sub_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 0x28 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_sub_gadgets[]; if (!gen_op(state, atomic_sub_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
                case 0x30 + 0x0: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_xor_gadgets[]; if (!gen_op(state, atomic_xor_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 0x30 + 0x1: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t atomic_xor_gadgets[]; if (!gen_op(state, atomic_xor_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break;
# 1378 "/Users/bbarrows/repos/ish/jit/gen.c"
                case 0x80: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; switch (modrm.opcode) {
                        case 0: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_add_gadgets[]; if (!gen_op(state, atomic_add_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 1: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_or_gadgets[]; if (!gen_op(state, atomic_or_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 2: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_adc_gadgets[]; if (!gen_op(state, atomic_adc_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 3: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_sbb_gadgets[]; if (!gen_op(state, atomic_sbb_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 4: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_and_gadgets[]; if (!gen_op(state, atomic_and_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 5: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_sub_gadgets[]; if (!gen_op(state, atomic_sub_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 6: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_xor_gadgets[]; if (!gen_op(state, atomic_xor_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; default: __use(0); do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;
                case 0x81: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); switch (modrm.opcode) {
                        case 0: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_add_gadgets[]; if (!gen_op(state, atomic_add_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 1: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_or_gadgets[]; if (!gen_op(state, atomic_or_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 2: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_adc_gadgets[]; if (!gen_op(state, atomic_adc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 3: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_sbb_gadgets[]; if (!gen_op(state, atomic_sbb_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 4: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_and_gadgets[]; if (!gen_op(state, atomic_and_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 5: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_sub_gadgets[]; if (!gen_op(state, atomic_sub_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 6: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_xor_gadgets[]; if (!gen_op(state, atomic_xor_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; default: __use(0); do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;
                case 0x83: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; switch (modrm.opcode) {
                        case 0: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_add_gadgets[]; if (!gen_op(state, atomic_add_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 1: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_or_gadgets[]; if (!gen_op(state, atomic_or_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 2: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_adc_gadgets[]; if (!gen_op(state, atomic_adc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 3: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_sbb_gadgets[]; if (!gen_op(state, atomic_sbb_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 4: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_and_gadgets[]; if (!gen_op(state, atomic_and_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 5: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_sub_gadgets[]; if (!gen_op(state, atomic_sub_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 6: __use(0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                                extern gadget_t atomic_xor_gadgets[]; if (!gen_op(state, atomic_xor_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; default: __use(0); do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;

                case 0x0f:
                    if (!tlb_read(tlb, state->ip, &insn, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, insn);
                    switch (insn) {
                        case 0xab: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t atomic_bts_gadgets[]; if (!gen_op(state, atomic_bts_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;
                        case 0xb3: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t atomic_btr_gadgets[]; if (!gen_op(state, atomic_btr_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;
                        case 0xbb: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t atomic_btc_gadgets[]; if (!gen_op(state, atomic_btc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;
# 1404 "/Users/bbarrows/repos/ish/jit/gen.c"
                        case 0xba: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; switch (modrm.opcode) {
                                case 5: __use(0); do {
                                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                                } while (0); do {
                                        extern gadget_t atomic_bts_gadgets[]; if (!gen_op(state, atomic_bts_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                                } while (0); break; case 6: __use(0); do {
                                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                                } while (0); do {
                                        extern gadget_t atomic_btr_gadgets[]; if (!gen_op(state, atomic_btr_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                                } while (0); break; case 7: __use(0); do {
                                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                                } while (0); do {
                                        extern gadget_t atomic_btc_gadgets[]; if (!gen_op(state, atomic_btc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                                } while (0); break; default: do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                } while (0);
                            }
                            break;

                        case 0xb0: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); if (modrm.type == modrm_reg) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t atomic_cmpxchg_gadgets[]; if (!gen_op(state, atomic_cmpxchg_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;
                        case 0xb1: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); if (modrm.type == modrm_reg) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t atomic_cmpxchg_gadgets[]; if (!gen_op(state, atomic_cmpxchg_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;

                        case 0xc0: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); if (modrm.type == modrm_reg) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t atomic_xadd_gadgets[]; if (!gen_op(state, atomic_xadd_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;
                        case 0xc1: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); if (modrm.type == modrm_reg) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t atomic_xadd_gadgets[]; if (!gen_op(state, atomic_xadd_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;

                        case 0xc7: if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); if (modrm.type == modrm_reg) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); switch (modrm.opcode) {
                                case 1: __use(0);
                                    gen_addr(state, &modrm, seg_gs, saved_ip); do {
                                        do {
                                            extern void gadget_atomic_cmpxchg8b(void); gen(state, (unsigned long)(gadget_atomic_cmpxchg8b));
                                        } while (0); gen(state, (unsigned long)(saved_ip));
                                    } while (0); break;
                                default: do {
                                        do {
                                            do {
                                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                        } while (0); return 0;
                                } while (0);
                        }
                            break;
                        default: __use(0); do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;
# 1435 "/Users/bbarrows/repos/ish/jit/gen.c"
                case 0xfe: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); switch (modrm.opcode) {
                        case 0: __use(0); do {
                                extern gadget_t atomic_inc_gadgets[]; if (!gen_op(state, atomic_inc_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 1: __use(0); do {
                                extern gadget_t atomic_dec_gadgets[]; if (!gen_op(state, atomic_dec_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; default: __use(0); do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;
                case 0xff: __use(0);
                    if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); if (modrm.type == modrm_reg) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); switch (modrm.opcode) {
                        case 0: __use(0); do {
                                extern gadget_t atomic_inc_gadgets[]; if (!gen_op(state, atomic_inc_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; case 1: __use(0); do {
                                extern gadget_t atomic_dec_gadgets[]; if (!gen_op(state, atomic_dec_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); break; default: __use(0); do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;

                default: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;

        case 0xf2:
            if (!tlb_read(tlb, state->ip, &insn, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, insn);
            switch (insn) {
                case 0x0f:
                    if (!tlb_read(tlb, state->ip, &insn, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, insn);
                    switch (insn) {
                        case 0x10: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                if (arg_xmm_modrm_val == arg_xmm_modrm_val && modrm.type != modrm_reg) {
                                    do {
                                        extern gadget_t vec_helper_load64_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_zload64, &vec_helper_load64_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                                    } while (0);
                                } else {
                                    do {
                                        extern gadget_t vec_helper_load64_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_load64, &vec_helper_load64_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                                    } while (0);
                                }
                            } while (0);
                            break;
                        case 0x11: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t vec_helper_store64_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_store64, &vec_helper_store64_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                            } while (0);
                            break;

                        case 0x18 ... 0x1f: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); break;
                        default: __use(0); do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;

                case 0xa6: __use(0); do {
                        do {
                            extern gadget_t cmps_gadgets[]; if (cmps_gadgets[sz(8) * size_count + rep_repnz] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(cmps_gadgets[sz(8) * size_count + rep_repnz]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xa7: __use(0); do {
                        do {
                            extern gadget_t cmps_gadgets[]; if (cmps_gadgets[sz(32) * size_count + rep_repnz] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(cmps_gadgets[sz(32) * size_count + rep_repnz]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xae: __use(0); do {
                        do {
                            extern gadget_t scas_gadgets[]; if (scas_gadgets[sz(8) * size_count + rep_repnz] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(scas_gadgets[sz(8) * size_count + rep_repnz]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xaf: __use(0); do {
                        do {
                            extern gadget_t scas_gadgets[]; if (scas_gadgets[sz(32) * size_count + rep_repnz] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(scas_gadgets[sz(32) * size_count + rep_repnz]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                default: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;

        case 0xf3:
            if (!tlb_read(tlb, state->ip, &insn, 8 / 8)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); state->ip += 8 / 8; __use(0, insn);
            switch (insn) {
                case 0x0f:

                    if (!tlb_read(tlb, state->ip, &insn, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, insn);
                    switch (insn) {
                        case 0x10: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                if (arg_xmm_modrm_val == arg_xmm_modrm_val && modrm.type != modrm_reg) {
                                    do {
                                        extern gadget_t vec_helper_load32_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_zload32, &vec_helper_load32_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                                    } while (0);
                                } else {
                                    do {
                                        extern gadget_t vec_helper_load32_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_load32, &vec_helper_load32_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                                    } while (0);
                                }
                            } while (0);
                            break;
                        case 0x11: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t vec_helper_store32_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_store32, &vec_helper_store32_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                            } while (0);
                            break;

                        case 0x7e: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t vec_helper_load64_gadgets[vec_arg_count]; if (!gen_vec(arg_xmm_modrm_val, arg_xmm_modrm_reg, (void (*)())vec_zload64, &vec_helper_load64_gadgets, state, &modrm, 0, saved_ip, seg_gs)) return 0;
                            } while (0);
                            break;

                        case 0x18 ... 0x1f: __use(0); if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); break;

                        case 0xbc: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t bsf_gadgets[]; if (!gen_op(state, bsf_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;
                        case 0xbd: __use(0);
                            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); do {
                                extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t bsr_gadgets[]; if (!gen_op(state, bsr_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); do {
                                extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_reg, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                            } while (0); break;

                        default: __use(0); do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                        } while (0);
                    }
                    break;

                case 0x90: __use(0); break;

                case 0xa4: __use(0); do {
                        do {
                            extern gadget_t movs_gadgets[]; if (movs_gadgets[sz(8) * size_count + rep_rep] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(movs_gadgets[sz(8) * size_count + rep_rep]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xa5: __use(0); do {
                        do {
                            extern gadget_t movs_gadgets[]; if (movs_gadgets[sz(32) * size_count + rep_rep] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(movs_gadgets[sz(32) * size_count + rep_rep]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xa6: __use(0); do {
                        do {
                            extern gadget_t cmps_gadgets[]; if (cmps_gadgets[sz(8) * size_count + rep_repz] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(cmps_gadgets[sz(8) * size_count + rep_repz]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xa7: __use(0); do {
                        do {
                            extern gadget_t cmps_gadgets[]; if (cmps_gadgets[sz(32) * size_count + rep_repz] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(cmps_gadgets[sz(32) * size_count + rep_repz]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xaa: __use(0); do {
                        do {
                            extern gadget_t stos_gadgets[]; if (stos_gadgets[sz(8) * size_count + rep_rep] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(stos_gadgets[sz(8) * size_count + rep_rep]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xab: __use(0); do {
                        do {
                            extern gadget_t stos_gadgets[]; if (stos_gadgets[sz(32) * size_count + rep_rep] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(stos_gadgets[sz(32) * size_count + rep_rep]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xac: __use(0); do {
                        do {
                            extern gadget_t lods_gadgets[]; if (lods_gadgets[sz(8) * size_count + rep_rep] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(lods_gadgets[sz(8) * size_count + rep_rep]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xad: __use(0); do {
                        do {
                            extern gadget_t lods_gadgets[]; if (lods_gadgets[sz(32) * size_count + rep_rep] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(lods_gadgets[sz(32) * size_count + rep_rep]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xae: __use(0); do {
                        do {
                            extern gadget_t scas_gadgets[]; if (scas_gadgets[sz(8) * size_count + rep_repz] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(scas_gadgets[sz(8) * size_count + rep_repz]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;
                case 0xaf: __use(0); do {
                        do {
                            extern gadget_t scas_gadgets[]; if (scas_gadgets[sz(32) * size_count + rep_repz] == ((void *)0)) do {
                                    do {
                                        do {
                                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                        } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                    } while (0); return 0;
                                } while (0); gen(state, (unsigned long)(scas_gadgets[sz(32) * size_count + rep_repz]));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break;

                case 0xc3: __use(0); do {
                        do {
                            extern void gadget_ret(void); gen(state, (unsigned long)(gadget_ret));
                        } while (0); gen(state, (unsigned long)(saved_ip)); gen(state, (unsigned long)(4 + 0));
                } while (0); end_block = 1; break;
                default: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;
# 1546 "/Users/bbarrows/repos/ish/jit/gen.c"
        case 0xf6: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); switch (modrm.opcode) {
                case 0: case 1: __use(0); if (!tlb_read(tlb, state->ip, &imm, 8 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 8 / 8; __use(0, (long long)imm); imm = (int8_t)(uint8_t)imm; do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t not_gadgets[]; if (not_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(not_gadgets[sz(8)]));
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); imm = 0; do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t mul_gadgets[]; if (mul_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(mul_gadgets[sz(8)]));
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t imul1_gadgets[]; if (imul1_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(imul1_gadgets[sz(8)]));
                } while (0); break; case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t div_gadgets[]; if (div_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(div_gadgets[sz(8)]));
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t idiv_gadgets[]; if (idiv_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(idiv_gadgets[sz(8)]));
                } while (0); break; default: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;
        case 0xf7: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); switch (modrm.opcode) {
                case 0: case 1: __use(0); if (!tlb_read(tlb, state->ip, &imm, 32 / 8)) do {
                            do {
                                do {
                                    extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                            } while (0); return 0;
                        } while (0); state->ip += 32 / 8; __use(0, (long long)imm); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t and_gadgets[]; if (!gen_op(state, and_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t not_gadgets[]; if (not_gadgets[sz(32)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(not_gadgets[sz(32)]));
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 3: __use(0); imm = 0; do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_imm, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t sub_gadgets[]; if (!gen_op(state, sub_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 4: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t mul_gadgets[]; if (mul_gadgets[sz(32)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(mul_gadgets[sz(32)]));
                } while (0); break; case 5: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t imul1_gadgets[]; if (imul1_gadgets[sz(32)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(imul1_gadgets[sz(32)]));
                } while (0); break; case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t div_gadgets[]; if (div_gadgets[sz(32)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(div_gadgets[sz(32)]));
                } while (0); break; case 7: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t idiv_gadgets[]; if (idiv_gadgets[sz(32)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(idiv_gadgets[sz(32)]));
                } while (0); break; default: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;

        case 0xfc: __use(0); do {
                extern void gadget_cld(void); gen(state, (unsigned long)(gadget_cld));
        } while (0); break;
        case 0xfd: __use(0); do {
                extern void gadget_std(void); gen(state, (unsigned long)(gadget_std));
        } while (0); break;
# 1573 "/Users/bbarrows/repos/ish/jit/gen.c"
        case 0xfe: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(inc_gadgets[sz(8)]));
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(8)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(dec_gadgets[sz(8)]));
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            do {
                                extern void gadget_call_indir(void); gen(state, (unsigned long)(gadget_call_indir));
                            } while (0); gen(state, (unsigned long)(saved_ip)); gen(state, (unsigned long)(-1)); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                        } while (0); state->block_patch_ip = state->size - 3; state->jump_ip[0] = state->size + -1; if (0 != 0) state->jump_ip[1] = state->size + 0; end_block = 1;
                } while (0); break; case 3: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0); case 4: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern void gadget_jmp_indir(void); gen(state, (unsigned long)(gadget_jmp_indir));
                } while (0); end_block = 1; break; case 5: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0); case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 8, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        do {
                            extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break; case 7: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;
        case 0xff: __use(0);
            if (!modrm_decode32(&state->ip, tlb, &modrm)) do {
                    do {
                        do {
                            extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                        } while (0); gen(state, (unsigned long)(13)); gen(state, (unsigned long)(saved_ip));
                    } while (0); return 0;
                } while (0); switch (modrm.opcode) {
                case 0: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t inc_gadgets[]; if (inc_gadgets[sz(32)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(inc_gadgets[sz(32)]));
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 1: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern gadget_t dec_gadgets[]; if (dec_gadgets[sz(32)] == ((void *)0)) do {
                                do {
                                    do {
                                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                                } while (0); return 0;
                            } while (0); gen(state, (unsigned long)(dec_gadgets[sz(32)]));
                } while (0); do {
                        extern gadget_t store_gadgets[]; if (!gen_op(state, store_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); break; case 2: __use(0); do {
                        do {
                            extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                        } while (0); do {
                            do {
                                extern void gadget_call_indir(void); gen(state, (unsigned long)(gadget_call_indir));
                            } while (0); gen(state, (unsigned long)(saved_ip)); gen(state, (unsigned long)(-1)); gen(state, (unsigned long)((state->ip | (1ul << 63)))); gen(state, (unsigned long)((state->ip | (1ul << 63))));
                        } while (0); state->block_patch_ip = state->size - 3; state->jump_ip[0] = state->size + -1; if (0 != 0) state->jump_ip[1] = state->size + 0; end_block = 1;
                } while (0); break; case 3: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0); case 4: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        extern void gadget_jmp_indir(void); gen(state, (unsigned long)(gadget_jmp_indir));
                } while (0); end_block = 1; break; case 5: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0); case 6: __use(0); do {
                        extern gadget_t load_gadgets[]; if (!gen_op(state, load_gadgets, arg_modrm_val, &modrm, &imm, 32, saved_ip, seg_gs, addr_offset)) return 0;
                } while (0); do {
                        do {
                            extern void gadget_push(void); gen(state, (unsigned long)(gadget_push));
                        } while (0); gen(state, (unsigned long)(saved_ip));
                } while (0); break; case 7: __use(0); do {
                        do {
                            do {
                                extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                            } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                        } while (0); return 0;
                } while (0);
            }
            break;

        default:
            __use(0);
            do {
                do {
                    do {
                        extern void gadget_interrupt(void); gen(state, (unsigned long)(gadget_interrupt));
                    } while (0); gen(state, (unsigned long)(6)); gen(state, (unsigned long)(saved_ip));
                } while (0); return 0;
            } while (0);
    }
    __use(0);
    return !end_block;
}
