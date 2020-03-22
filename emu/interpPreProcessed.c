# 1 "/Users/bbarrows/repos/ish2/emu/interp.c"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 363 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "/Users/bbarrows/repos/ish2/emu/interp.c" 2
# 1 "/Users/bbarrows/repos/ish2/emu/cpu.h" 1

#pragma clang module import Darwin.C.stddef /* clang -E: implicit import for #include <stddef.h> */
# 1 "/Users/bbarrows/repos/ish2/misc.h" 1

# 1 "/Users/bbarrows/Downloads/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.0.sdk/usr/include/assert.h" 1 3 4
# 42 "/Users/bbarrows/Downloads/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.0.sdk/usr/include/assert.h" 3 4
#pragma clang module import Darwin.cdefs /* clang -E: implicit import for #include <sys/cdefs.h> */
# 76 "/Users/bbarrows/Downloads/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.0.sdk/usr/include/assert.h" 3 4
void __assert_rtn(const char *, const char *, int, const char *) __attribute__((__noreturn__)) __attribute__((__cold__)) __attribute__((__disable_tail_calls__));
# 5 "/Users/bbarrows/repos/ish2/misc.h" 2
#pragma clang module import Darwin.C.stdio   /* clang -E: implicit import for #include <stdio.h> */
#pragma clang module import Darwin.C.stdlib  /* clang -E: implicit import for #include <stdlib.h> */
#pragma clang module import Darwin.C.stdint  /* clang -E: implicit import for #include <stdint.h> */
#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */
# 1 "/Users/bbarrows/Downloads/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/11.0.0/include/stdnoreturn.h" 1 3 4
# 10 "/Users/bbarrows/repos/ish2/misc.h" 2
#pragma clang module import Darwin.POSIX.sys.types /* clang -E: implicit import for #include <sys/types.h> */
# 40 "/Users/bbarrows/repos/ish2/misc.h"
static inline void __use(int dummy __attribute__((unused)), ...)
{
}
# 58 "/Users/bbarrows/repos/ish2/misc.h"
typedef int64_t sqword_t;
typedef uint64_t qword_t;
typedef uint32_t dword_t;
typedef int32_t sdword_t;
typedef uint16_t word_t;
typedef uint8_t byte_t;

typedef dword_t addr_t;
typedef dword_t uint_t;
typedef sdword_t int_t;

typedef sdword_t pid_t_;
typedef dword_t uid_t_;
typedef word_t mode_t_;
typedef sqword_t off_t_;
typedef dword_t time_t_;
typedef dword_t clock_t_;
# 6 "/Users/bbarrows/repos/ish2/emu/cpu.h" 2
# 1 "/Users/bbarrows/repos/ish2/emu/float80.h" 1

#pragma clang module import Darwin.C.stdint  /* clang -E: implicit import for #include <stdint.h> */
#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */

typedef struct
{
    uint64_t signif;
    union {
        uint16_t signExp;
        struct
        {
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

enum f80_rounding_mode
{
    round_to_nearest = 0,
    round_down = 1,
    round_up = 2,
    round_chop = 3,
};
extern __thread enum f80_rounding_mode f80_rounding_mode;
# 7 "/Users/bbarrows/repos/ish2/emu/cpu.h" 2
# 1 "/Users/bbarrows/repos/ish2/emu/memory.h" 1

#pragma clang module import Darwin.C.stdatomic  /* clang -E: implicit import for #include <stdatomic.h> */
#pragma clang module import Darwin.POSIX.unistd /* clang -E: implicit import for #include <unistd.h> */
# 1 "/Users/bbarrows/repos/ish2/util/list.h" 1

#pragma clang module import Darwin.POSIX.unistd /* clang -E: implicit import for #include <unistd.h> */
#pragma clang module import Darwin.C.stdbool    /* clang -E: implicit import for #include <stdbool.h> */
#pragma clang module import Darwin.C.stddef     /* clang -E: implicit import for #include <stddef.h> */

struct list
{
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
    if (list_null(list))
        list_init(list);
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
    if (!list_null(item))
        list_remove(item);
}
# 89 "/Users/bbarrows/repos/ish2/util/list.h"
static inline unsigned long list_size(struct list *list)
{
    unsigned long count = 0;
    struct list *item;
    for (item = (list)->next; item != (list); item = item->next)
    {
        count++;
    }
    return count;
}
# 7 "/Users/bbarrows/repos/ish2/emu/memory.h" 2
# 1 "/Users/bbarrows/repos/ish2/util/sync.h" 1

#pragma clang module import Darwin.C.stdatomic           /* clang -E: implicit import for #include <stdatomic.h> */
#pragma clang module import Darwin.POSIX.pthread.pthread /* clang -E: implicit import for #include <pthread.h> */
#pragma clang module import Darwin.C.stdbool             /* clang -E: implicit import for #include <stdbool.h> */
#pragma clang module import Darwin.C.setjmp              /* clang -E: implicit import for #include <setjmp.h> */

typedef struct
{
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

typedef struct
{
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
    if (sigsetjmp(unwind_buf, 1))
    {
        should_unwind = 0;
        return 1;
    }
    else
    {
        should_unwind = 1;
        return 0;
    }
}
static inline void sigunwind_end()
{
    should_unwind = 0;
}
# 8 "/Users/bbarrows/repos/ish2/emu/memory.h" 2

typedef dword_t page_t;

struct mem
{
    atomic_uint changes;
    struct pt_entry **pgdir;
    int pgdir_used;

    wrlock_t lock;
};

void mem_init(struct mem *mem);

void mem_destroy(struct mem *mem);

struct pt_entry *mem_pt(struct mem *mem, page_t page);

void mem_next_page(struct mem *mem, page_t *page);

typedef dword_t pages_t;

struct data
{
    void *data;
    size_t size;
    atomic_uint refcount;

    struct fd *fd;
    size_t file_offset;
    const char *name;
};
struct pt_entry
{
    struct data *data;
    size_t offset;
    unsigned flags;
};
# 94 "/Users/bbarrows/repos/ish2/emu/memory.h"
_Bool pt_is_hole(struct mem *mem, page_t start, pages_t pages);
page_t pt_find_hole(struct mem *mem, pages_t size);

int pt_map(struct mem *mem, page_t start, pages_t pages, void *memory, size_t offset, unsigned flags);

int pt_map_nothing(struct mem *mem, page_t page, pages_t pages, unsigned flags);

int pt_unmap(struct mem *mem, page_t start, pages_t pages);

int pt_unmap_always(struct mem *mem, page_t start, pages_t pages);

int pt_set_flags(struct mem *mem, page_t start, pages_t pages, int flags);

int pt_copy_on_write(struct mem *src, struct mem *dst, page_t start, page_t pages);

void *mem_ptr(struct mem *mem, addr_t addr, int type);
int mem_segv_reason(struct mem *mem, addr_t addr);

extern size_t real_page_size;
# 8 "/Users/bbarrows/repos/ish2/emu/cpu.h" 2

struct cpu_state;
struct tlb;
void cpu_run(struct cpu_state *cpu);
int cpu_step32(struct cpu_state *cpu, struct tlb *tlb);
int cpu_step16(struct cpu_state *cpu, struct tlb *tlb);

union xmm_reg {
    qword_t qw[2];
    dword_t dw[4];
};

struct cpu_state
{
    struct mem *mem;
    struct jit *jit;
# 41 "/Users/bbarrows/repos/ish2/emu/cpu.h"
    union {
        dword_t eax;
        word_t ax;
        struct
        {
            byte_t al;
            byte_t ah;
        };
    };
    ;
    union {
        dword_t ebx;
        word_t bx;
        struct
        {
            byte_t bl;
            byte_t bh;
        };
    };
    ;
    union {
        dword_t ecx;
        word_t cx;
        struct
        {
            byte_t cl;
            byte_t ch;
        };
    };
    ;
    union {
        dword_t edx;
        word_t dx;
        struct
        {
            byte_t dl;
            byte_t dh;
        };
    };
    ;
    union {
        dword_t esi;
        word_t si;
    };
    ;
    union {
        dword_t edi;
        word_t di;
    };
    ;
    union {
        dword_t ebp;
        word_t bp;
    };
    ;
    union {
        dword_t esp;
        word_t sp;
    };
    ;

    union xmm_reg xmm[8];

    dword_t eip;

    union {
        dword_t eflags;
        struct
        {
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
        struct
        {
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
        struct
        {
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
        struct
        {
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
# 159 "/Users/bbarrows/repos/ish2/emu/cpu.h"
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

enum reg32
{
    reg_eax = 0,
    reg_ecx,
    reg_edx,
    reg_ebx,
    reg_esp,
    reg_ebp,
    reg_esi,
    reg_edi,
    reg_count,
    reg_none = reg_count,
};

static inline const char *reg32_name(enum reg32 reg)
{
    switch (reg)
    {
    case reg_eax:
        return "eax";
    case reg_ecx:
        return "ecx";
    case reg_edx:
        return "edx";
    case reg_ebx:
        return "ebx";
    case reg_esp:
        return "esp";
    case reg_ebp:
        return "ebp";
    case reg_esi:
        return "esi";
    case reg_edi:
        return "edi";
    case reg_none:
        return "?";
    }
}
# 2 "/Users/bbarrows/repos/ish2/emu/interp.c" 2
# 1 "/Users/bbarrows/repos/ish2/emu/cpuid.h" 1

static inline void do_cpuid(dword_t *eax, dword_t *ebx, dword_t *ecx, dword_t *edx)
{
    dword_t leaf = *eax;
    switch (leaf)
    {
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
# 3 "/Users/bbarrows/repos/ish2/emu/interp.c" 2
# 1 "/Users/bbarrows/repos/ish2/emu/modrm.h" 1

# 1 "/Users/bbarrows/repos/ish2/debug.h" 1

#pragma clang module import Darwin.C.stdio  /* clang -E: implicit import for #include <stdio.h> */
#pragma clang module import Darwin.C.stdlib /* clang -E: implicit import for #include <stdlib.h> */

void printk(const char *msg, ...);
void vprintk(const char *msg, va_list args);
# 74 "/Users/bbarrows/repos/ish2/debug.h"
extern void (*die_handler)(const char *msg);
_Noreturn void die(const char *msg, ...);
# 5 "/Users/bbarrows/repos/ish2/emu/modrm.h" 2

# 1 "/Users/bbarrows/repos/ish2/emu/tlb.h" 1

#pragma clang module import Darwin.C.string /* clang -E: implicit import for #include <string.h> */

struct tlb_entry
{
    page_t page;
    page_t page_if_writable;
    uintptr_t data_minus_addr;
};

struct tlb
{
    struct mem *mem;
    page_t dirty_page;
    struct tlb_entry entries[(1 << 10)];
};

void tlb_init(struct tlb *tlb, struct mem *mem);
void tlb_free(struct tlb *tlb);
void tlb_flush(struct tlb *tlb);
void *tlb_handle_miss(struct tlb *tlb, addr_t addr, int type);

inline __attribute__((always_inline)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) void *__tlb_read_ptr(struct tlb *tlb, addr_t addr)
{
    struct tlb_entry entry = tlb->entries[(((addr >> 12) & ((1 << 10) - 1)) ^ (addr >> (12 + 10)))];
    if (entry.page == (addr & 0xfffff000))
    {
        void *address = (void *)(entry.data_minus_addr + addr);
        (__builtin_expect(!(address != ((void *)0)), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish2/emu/tlb.h", 36, "address != NULL") : (void)0);
        return address;
    }
    return tlb_handle_miss(tlb, addr, 0);
}

_Bool __tlb_read_cross_page(struct tlb *tlb, addr_t addr, char *out, unsigned size);

inline __attribute__((always_inline)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) _Bool tlb_read(struct tlb *tlb, addr_t addr, void *out, unsigned size)
{
    if (((addr) & ((1 << 12) - 1)) > (1 << 12) - size)
        return __tlb_read_cross_page(tlb, addr, out, size);
    void *ptr = __tlb_read_ptr(tlb, addr);
    if (ptr == ((void *)0))
        return 0;
    __builtin___memcpy_chk(out, ptr, size, __builtin_object_size(out, 0));
    return 1;
}

inline __attribute__((always_inline)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) void *__tlb_write_ptr(struct tlb *tlb, addr_t addr)
{
    struct tlb_entry entry = tlb->entries[(((addr >> 12) & ((1 << 10) - 1)) ^ (addr >> (12 + 10)))];
    if (entry.page_if_writable == (addr & 0xfffff000))
    {
        tlb->dirty_page = (addr & 0xfffff000);
        void *address = (void *)(entry.data_minus_addr + addr);
        (__builtin_expect(!(address != ((void *)0)), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish2/emu/tlb.h", 59, "address != NULL") : (void)0);
        return address;
    }
    return tlb_handle_miss(tlb, addr, 1);
}
_Bool __tlb_write_cross_page(struct tlb *tlb, addr_t addr, const char *value, unsigned size);
inline __attribute__((always_inline)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) _Bool tlb_write(struct tlb *tlb, addr_t addr, const void *value, unsigned size)
{
    if (((addr) & ((1 << 12) - 1)) > (1 << 12) - size)
        return __tlb_write_cross_page(tlb, addr, value, size);
    void *ptr = __tlb_write_ptr(tlb, addr);
    if (ptr == ((void *)0))
        return 0;
    __builtin___memcpy_chk(ptr, value, size, __builtin_object_size(ptr, 0));
    return 1;
}
# 8 "/Users/bbarrows/repos/ish2/emu/modrm.h" 2

struct modrm
{
    union {
        enum reg32 reg;
        int opcode;
    };
    enum
    {
        modrm_reg,
        modrm_mem,
        modrm_mem_si
    } type;
    union {
        enum reg32 base;
        int rm_opcode;
    };
    int32_t offset;
    enum reg32 index;
    enum
    {
        times_1 = 0,
        times_2 = 1,
        times_4 = 2,
    } shift;
};

enum
{
    rm_sib = reg_esp,
    rm_none = reg_esp,
    rm_disp32 = reg_ebp,
};

static inline _Bool modrm_decode32(addr_t *ip, struct tlb *tlb, struct modrm *modrm)
{

    byte_t modrm_byte;
    if (!tlb_read(tlb, *ip, &(modrm_byte), sizeof(modrm_byte)))
        return 0;
    *ip += sizeof(modrm_byte);
    ;

    enum
    {
        mode_disp0,
        mode_disp8,
        mode_disp32,
        mode_reg,
    } mode = ((modrm_byte & 0b11000000) >> 6);
    modrm->type = modrm_mem;
    modrm->reg = ((modrm_byte & 0b00111000) >> 3);
    modrm->rm_opcode = ((modrm_byte & 0b00000111) >> 0);
    if (mode == mode_reg)
    {
        modrm->type = modrm_reg;
    }
    else if (modrm->rm_opcode == rm_disp32 && mode == mode_disp0)
    {
        modrm->base = reg_none;
        mode = mode_disp32;
    }
    else if (modrm->rm_opcode == rm_sib && mode != mode_reg)
    {
        byte_t sib_byte;
        if (!tlb_read(tlb, *ip, &(sib_byte), sizeof(sib_byte)))
            return 0;
        *ip += sizeof(sib_byte);
        ;
        modrm->base = ((sib_byte & 0b00000111) >> 0);

        if (modrm->rm_opcode == rm_disp32)
        {
            if (mode == mode_disp0)
            {
                modrm->base = reg_none;
                mode = mode_disp32;
            }
            else
            {
                modrm->base = reg_ebp;
            }
        }
        modrm->index = ((sib_byte & 0b00111000) >> 3);
        modrm->shift = ((sib_byte & 0b11000000) >> 6);
        if (modrm->index != rm_none)
            modrm->type = modrm_mem_si;
    }

    if (mode == mode_disp0)
    {
        modrm->offset = 0;
    }
    else if (mode == mode_disp8)
    {
        int8_t offset;
        if (!tlb_read(tlb, *ip, &(offset), sizeof(offset)))
            return 0;
        *ip += sizeof(offset);
        ;
        modrm->offset = offset;
    }
    else if (mode == mode_disp32)
    {
        int32_t offset;
        if (!tlb_read(tlb, *ip, &(offset), sizeof(offset)))
            return 0;
        *ip += sizeof(offset);
        ;
        modrm->offset = offset;
    }

    __use(0, reg32_name(modrm->reg), modrm->opcode);
    __use(0, reg32_name(modrm->base));
    if (modrm->type != modrm_reg)
        __use(0, modrm->offset < 0 ? "-" : "", modrm->offset);
    if (modrm->type == modrm_mem_si)
        __use(0, reg32_name(modrm->index), modrm->shift);

    return 1;
}
# 4 "/Users/bbarrows/repos/ish2/emu/interp.c" 2
# 1 "/Users/bbarrows/repos/ish2/emu/regid.h" 1

typedef uint8_t reg_id_t;

static inline const char *regid8_name(uint8_t reg_id)
{
    switch (reg_id)
    {
    case __builtin_offsetof(struct cpu_state, al):
        return "al";
    case __builtin_offsetof(struct cpu_state, bl):
        return "bl";
    case __builtin_offsetof(struct cpu_state, cl):
        return "cl";
    case __builtin_offsetof(struct cpu_state, dl):
        return "dl";
    case __builtin_offsetof(struct cpu_state, ah):
        return "ah";
    case __builtin_offsetof(struct cpu_state, bh):
        return "bh";
    case __builtin_offsetof(struct cpu_state, ch):
        return "ch";
    case __builtin_offsetof(struct cpu_state, dh):
        return "dh";
    }
    return "??";
}
static inline const char *regid16_name(uint8_t reg_id)
{
    switch (reg_id)
    {
    case __builtin_offsetof(struct cpu_state, ax):
        return "ax";
    case __builtin_offsetof(struct cpu_state, bx):
        return "bx";
    case __builtin_offsetof(struct cpu_state, cx):
        return "cx";
    case __builtin_offsetof(struct cpu_state, dx):
        return "dx";
    case __builtin_offsetof(struct cpu_state, si):
        return "si";
    case __builtin_offsetof(struct cpu_state, di):
        return "di";
    case __builtin_offsetof(struct cpu_state, bp):
        return "bp";
    case __builtin_offsetof(struct cpu_state, sp):
        return "sp";
    }
    return "??";
}
static inline const char *regid32_name(uint8_t reg_id)
{
    switch (reg_id)
    {
    case __builtin_offsetof(struct cpu_state, eax):
        return "eax";
    case __builtin_offsetof(struct cpu_state, ebx):
        return "ebx";
    case __builtin_offsetof(struct cpu_state, ecx):
        return "ecx";
    case __builtin_offsetof(struct cpu_state, edx):
        return "edx";
    case __builtin_offsetof(struct cpu_state, esi):
        return "esi";
    case __builtin_offsetof(struct cpu_state, edi):
        return "edi";
    case __builtin_offsetof(struct cpu_state, ebp):
        return "ebp";
    case __builtin_offsetof(struct cpu_state, esp):
        return "esp";
    }
    return "???";
}

struct regptr
{

    reg_id_t reg8_id;
    reg_id_t reg16_id;
    reg_id_t reg32_id;
    reg_id_t reg128_id;
};
static __attribute__((unused)) const char *regptr_name(struct regptr regptr)
{
    static char buf[15];
    __builtin___sprintf_chk(buf, 0, __builtin_object_size(buf, 2 > 1 ? 1 : 0), "%s/%s/%s", regid8_name(regptr.reg8_id), regid16_name(regptr.reg16_id), regid32_name(regptr.reg32_id));

    return buf;
}
# 71 "/Users/bbarrows/repos/ish2/emu/regid.h"
static inline struct regptr regptr_from_reg(enum reg32 reg)
{
    switch (reg)
    {
    case reg_eax:
        return ((struct regptr){
            .reg32_id = __builtin_offsetof(struct cpu_state, eax),
            .reg16_id = __builtin_offsetof(struct cpu_state, ax),
            .reg8_id = __builtin_offsetof(struct cpu_state, al),
            .reg128_id = __builtin_offsetof(struct cpu_state, xmm[0]),
        });
    case reg_ecx:
        return ((struct regptr){
            .reg32_id = __builtin_offsetof(struct cpu_state, ecx),
            .reg16_id = __builtin_offsetof(struct cpu_state, cx),
            .reg8_id = __builtin_offsetof(struct cpu_state, cl),
            .reg128_id = __builtin_offsetof(struct cpu_state, xmm[1]),
        });
    case reg_edx:
        return ((struct regptr){
            .reg32_id = __builtin_offsetof(struct cpu_state, edx),
            .reg16_id = __builtin_offsetof(struct cpu_state, dx),
            .reg8_id = __builtin_offsetof(struct cpu_state, dl),
            .reg128_id = __builtin_offsetof(struct cpu_state, xmm[2]),
        });
    case reg_ebx:
        return ((struct regptr){
            .reg32_id = __builtin_offsetof(struct cpu_state, ebx),
            .reg16_id = __builtin_offsetof(struct cpu_state, bx),
            .reg8_id = __builtin_offsetof(struct cpu_state, bl),
            .reg128_id = __builtin_offsetof(struct cpu_state, xmm[3]),
        });
    case reg_esp:
        return ((struct regptr){
            .reg32_id = __builtin_offsetof(struct cpu_state, esp),
            .reg16_id = __builtin_offsetof(struct cpu_state, sp),
            .reg8_id = __builtin_offsetof(struct cpu_state, ah),
            .reg128_id = __builtin_offsetof(struct cpu_state, xmm[4]),
        });
    case reg_ebp:
        return ((struct regptr){
            .reg32_id = __builtin_offsetof(struct cpu_state, ebp),
            .reg16_id = __builtin_offsetof(struct cpu_state, bp),
            .reg8_id = __builtin_offsetof(struct cpu_state, ch),
            .reg128_id = __builtin_offsetof(struct cpu_state, xmm[5]),
        });
    case reg_esi:
        return ((struct regptr){
            .reg32_id = __builtin_offsetof(struct cpu_state, esi),
            .reg16_id = __builtin_offsetof(struct cpu_state, si),
            .reg8_id = __builtin_offsetof(struct cpu_state, dh),
            .reg128_id = __builtin_offsetof(struct cpu_state, xmm[6]),
        });
    case reg_edi:
        return ((struct regptr){
            .reg32_id = __builtin_offsetof(struct cpu_state, edi),
            .reg16_id = __builtin_offsetof(struct cpu_state, di),
            .reg8_id = __builtin_offsetof(struct cpu_state, bh),
            .reg128_id = __builtin_offsetof(struct cpu_state, xmm[7]),
        });
    case reg_none:
        return (struct regptr){};
    default:
        die("invalid register");
    }
}
# 5 "/Users/bbarrows/repos/ish2/emu/interp.c" 2

# 1 "/Users/bbarrows/repos/ish2/emu/interrupt.h" 1
# 8 "/Users/bbarrows/repos/ish2/emu/interp.c" 2

# 1 "/Users/bbarrows/repos/ish2/kernel/calls.h" 1

# 1 "/Users/bbarrows/repos/ish2/kernel/task.h" 1

#pragma clang module import Darwin.POSIX.pthread.pthread /* clang -E: implicit import for #include <pthread.h> */

# 1 "/Users/bbarrows/repos/ish2/kernel/mm.h" 1

struct mm
{
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

struct mm *mm_new(void);

struct mm *mm_copy(struct mm *mm);

void mm_retain(struct mm *mem);

void mm_release(struct mm *mem);
# 7 "/Users/bbarrows/repos/ish2/kernel/task.h" 2
# 1 "/Users/bbarrows/repos/ish2/kernel/fs.h" 1

# 1 "/Users/bbarrows/repos/ish2/fs/stat.h" 1

struct statbuf
{
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

struct oldstat
{
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

struct newstat
{
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

struct newstat64
{
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

struct statfsbuf
{
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

struct statfs_
{
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

struct statfs64_
{
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
# 7 "/Users/bbarrows/repos/ish2/kernel/fs.h" 2
# 1 "/Users/bbarrows/repos/ish2/fs/dev.h" 1

#pragma clang module import Darwin.POSIX.sys.types /* clang -E: implicit import for #include <sys/types.h> */

# 1 "/Users/bbarrows/repos/ish2/fs/fd.h" 1

#pragma clang module import Darwin.POSIX.dirent /* clang -E: implicit import for #include <dirent.h> */

# 1 "/Users/bbarrows/repos/ish2/util/bits.h" 1

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
# 8 "/Users/bbarrows/repos/ish2/fs/fd.h" 2

# 1 "/Users/bbarrows/repos/ish2/fs/proc.h" 1

struct proc_entry
{
    struct proc_dir_entry *meta;
    pid_t_ pid;
    sdword_t fd;
};

struct proc_data
{
    char *data;
    size_t size;
    size_t capacity;
};

struct proc_dir_entry
{
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
# 10 "/Users/bbarrows/repos/ish2/fs/fd.h" 2
# 1 "/Users/bbarrows/repos/ish2/fs/sockrestart.h" 1
# 15 "/Users/bbarrows/repos/ish2/fs/sockrestart.h"
#pragma clang module import Darwin.C.stdbool /* clang -E: implicit import for #include <stdbool.h> */

struct fd;

void sockrestart_begin_listen(struct fd *sock);
void sockrestart_end_listen(struct fd *sock);
void sockrestart_begin_listen_wait(struct fd *sock);
void sockrestart_end_listen_wait(struct fd *sock);
_Bool sockrestart_should_restart_listen_wait(void);
void sockrestart_on_suspend(void);
void sockrestart_on_resume(void);

struct fd_sockrestart
{
    struct list listen;
};

struct task_sockrestart
{
    int count;
    _Bool punt;
    struct list listen;
};
# 11 "/Users/bbarrows/repos/ish2/fs/fd.h" 2

struct fd
{
    atomic_uint refcount;
    unsigned flags;
    mode_t_ type;
    const struct fd_ops *ops;
    struct list poll_fds;
    lock_t poll_lock;
    unsigned long offset;

    union {

        struct
        {
            struct tty *tty;

            struct list tty_other_fds;
        };
        struct
        {
            struct poll *poll;
        } epollfd;
        struct
        {
            uint64_t val;
        } eventfd;
        struct
        {
            struct timer *timer;
            uint64_t expirations;
        } timerfd;
        struct
        {
            int domain;
            int type;
            int protocol;

            struct inode_data *unix_name_inode;
            struct unix_abstract *unix_name_abstract;

            struct fd *unix_peer;
            cond_t unix_got_peer;

            struct list unix_scm;
            struct ucred_
            {
                pid_t_ pid;
                uid_t_ uid;
                uid_t_ gid;
            } unix_cred;
        } socket;

        struct
        {

            uint64_t generation;

            void *buffer;

            size_t buffer_cap;

            size_t buffer_len;
        } clipboard;

        void *data;
    };

    union {
        struct
        {
            struct proc_entry entry;
            unsigned dir_index;
            struct proc_data data;
        } proc;
        struct
        {
            int num;
        } devpts;
        struct
        {
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

struct fd *fd_create(const struct fd_ops *ops);
struct fd *fd_retain(struct fd *fd);
int fd_close(struct fd *fd);

int fd_getflags(struct fd *fd);
int fd_setflags(struct fd *fd, int flags);

struct dir_entry
{
    qword_t inode;
    char name[255 + 1];
};

struct fd_ops
{

    ssize_t (*read)(struct fd *fd, void *buf, size_t bufsize);
    ssize_t (*write)(struct fd *fd, const void *buf, size_t bufsize);
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

struct fdtable
{
    atomic_uint refcount;
    unsigned size;
    struct fd **files;
    bits_t *cloexec;
    lock_t lock;
};

struct fdtable *fdtable_new(int size);
void fdtable_release(struct fdtable *table);
struct fdtable *fdtable_copy(struct fdtable *table);
void fdtable_free(struct fdtable *table);
void fdtable_do_cloexec(struct fdtable *table);
struct fd *fdtable_get(struct fdtable *table, fd_t f);

struct fd *f_get(fd_t f);

fd_t f_install(struct fd *fd, int flags);
int f_close(fd_t f);
# 9 "/Users/bbarrows/repos/ish2/fs/dev.h" 2

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
    return dev_make(((int32_t)(((u_int32_t)(dev) >> 24) & 0xff)), ((int32_t)((dev)&0xffffff)));
}

struct dev_ops
{
    int (*open)(int major, int minor, struct fd *fd);
    struct fd_ops fd;
};

extern struct dev_ops *block_devs[];
extern struct dev_ops *char_devs[];

int dev_open(int major, int minor, int type, struct fd *fd);

extern struct dev_ops null_dev;
# 8 "/Users/bbarrows/repos/ish2/kernel/fs.h" 2

#pragma clang module import Darwin.POSIX.dirent /* clang -E: implicit import for #include <dirent.h> */
#pragma clang module import SQLite3             /* clang -E: implicit import for #include <sqlite3.h> */

struct fs_info
{
    atomic_uint refcount;
    mode_t_ umask;
    struct fd *pwd;
    struct fd *root;
    lock_t lock;
};
struct fs_info *fs_info_new(void);
struct fs_info *fs_info_copy(struct fs_info *fs);
void fs_info_release(struct fs_info *fs);

void fs_chdir(struct fs_info *fs, struct fd *pwd);

struct attr
{
    enum attr_type
    {
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

struct fd *generic_open(const char *path, int flags, int mode);
struct fd *generic_openat(struct fd *at, const char *path, int flags, int mode);
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

struct mount
{
    const char *point;
    const char *source;
    int flags;
    const struct fs_ops *fs;
    unsigned refcount;
    struct list mounts;

    int root_fd;
    union {
        void *data;
        struct
        {
            sqlite3 *db;
            struct
            {
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

struct mount *mount_find(char *path);
void mount_retain(struct mount *mount);
void mount_release(struct mount *mount);

int do_mount(const struct fs_ops *fs, const char *source, const char *point, int flags);
int do_umount(const char *point);
int mount_remove(struct mount *mount);
extern struct list mounts;
# 134 "/Users/bbarrows/repos/ish2/kernel/fs.h"
struct fs_ops
{
    const char *name;
    int magic;

    int (*mount)(struct mount *mount);
    int (*umount)(struct mount *mount);
    int (*statfs)(struct mount *mount, struct statfsbuf *stat);

    struct fd *(*open)(struct mount *mount, const char *path, int flags, int mode);
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

struct mount *find_mount_and_trim_path(char *path);
const char *fix_path(const char *path);

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

struct fd *adhoc_fd_create(const struct fd_ops *ops);

extern const struct fs_ops realfs;
extern const struct fs_ops procfs;
extern const struct fs_ops fakefs;
extern const struct fs_ops devptsfs;
extern const struct fs_ops tmpfs;
# 8 "/Users/bbarrows/repos/ish2/kernel/task.h" 2
# 1 "/Users/bbarrows/repos/ish2/kernel/signal.h" 1

struct task;

typedef qword_t sigset_t_;
# 18 "/Users/bbarrows/repos/ish2/kernel/signal.h"
struct sigaction_
{
    addr_t handler;
    dword_t flags;
    addr_t restorer;
    sigset_t_ mask;
} __attribute__((packed));
# 67 "/Users/bbarrows/repos/ish2/kernel/signal.h"
union sigval_ {
    int_t sv_int;
    addr_t sv_ptr;
};

struct siginfo_
{
    int_t sig;
    int_t sig_errno;
    int_t code;
    union {
        struct
        {
            pid_t_ pid;
            uid_t_ uid;
        } kill;
        struct
        {
            pid_t_ pid;
            uid_t_ uid;
            int_t status;
            clock_t_ utime;
            clock_t_ stime;
        } child;
        struct
        {
            addr_t addr;
        } fault;
        struct
        {
            addr_t addr;
            int_t syscall;
        } sigsys;
    };
};

static const struct siginfo_ SIGINFO_NIL = {
    .code = 128,
};

struct sigqueue
{
    struct list queue;
    struct siginfo_ info;
};

void send_signal(struct task *task, int sig, struct siginfo_ info);

void deliver_signal(struct task *task, int sig, struct siginfo_ info);

_Bool try_self_signal(int sig);

int send_group_signal(dword_t pgid, int sig, struct siginfo_ info);

void receive_signals(void);

void sigmask_set_temp(sigset_t_ mask);

struct sighand
{
    atomic_uint refcount;
    struct sigaction_ action[64];
    addr_t altstack;
    dword_t altstack_size;
    lock_t lock;
};
struct sighand *sighand_new(void);
struct sighand *sighand_copy(struct sighand *sighand);
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
    (__builtin_expect(!(sig >= 1 && sig <= 64), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish2/kernel/signal.h", 148, "sig >= 1 && sig <= NUM_SIGS") : (void)0);
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

struct stack_t_
{
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

struct sigcontext_
{
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

struct ucontext_
{
    uint_t flags;
    uint_t link;
    struct stack_t_ stack;
    struct sigcontext_ mcontext;
    sigset_t_ sigmask;
} __attribute__((packed));

struct fpreg_
{
    word_t significand[4];
    word_t exponent;
};

struct fpxreg_
{
    word_t significand[4];
    word_t exponent;
    word_t padding[3];
};

struct xmmreg_
{
    uint32_t element[4];
};

struct fpstate_
{

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

struct sigframe_
{
    addr_t restorer;
    dword_t sig;
    struct sigcontext_ sc;
    struct fpstate_ fpstate;
    dword_t extramask;
    char retcode[8];
};

struct rt_sigframe_
{
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
# 9 "/Users/bbarrows/repos/ish2/kernel/task.h" 2
# 1 "/Users/bbarrows/repos/ish2/kernel/resource.h" 1

# 1 "/Users/bbarrows/repos/ish2/kernel/time.h" 1

dword_t sys_time(addr_t time_out);
dword_t sys_stime(addr_t time);

dword_t sys_clock_gettime(dword_t clock, addr_t tp);
dword_t sys_clock_settime(dword_t clock, addr_t tp);
dword_t sys_clock_getres(dword_t clock, addr_t res_addr);

struct timeval_
{
    dword_t sec;
    dword_t usec;
};
struct timespec_
{
    dword_t sec;
    dword_t nsec;
};
struct timezone_
{
    dword_t minuteswest;
    dword_t dsttime;
};

static inline clock_t_ clock_from_timeval(struct timeval_ timeval)
{
    return timeval.sec * 100 + timeval.usec / 10000;
}

struct itimerval_
{
    struct timeval_ interval;
    struct timeval_ value;
};

struct itimerspec_
{
    struct timespec_ interval;
    struct timespec_ value;
};

struct tms_
{
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
# 4 "/Users/bbarrows/repos/ish2/kernel/resource.h" 2

typedef qword_t rlim_t_;
typedef dword_t rlim32_t_;

struct rlimit_
{
    rlim_t_ cur;
    rlim_t_ max;
};

struct rlimit32_
{
    rlim32_t_ cur;
    rlim32_t_ max;
};
# 37 "/Users/bbarrows/repos/ish2/kernel/resource.h"
dword_t sys_getrlimit32(dword_t resource, addr_t rlim_addr);
dword_t sys_setrlimit32(dword_t resource, addr_t rlim_addr);
dword_t sys_prlimit64(pid_t_ pid, dword_t resource, addr_t new_limit_addr, addr_t old_limit_addr);
dword_t sys_old_getrlimit32(dword_t resource, addr_t rlim_addr);

rlim_t_ rlimit(int resource);

struct rusage_
{
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
# 10 "/Users/bbarrows/repos/ish2/kernel/task.h" 2

# 1 "/Users/bbarrows/repos/ish2/util/timer.h" 1

#pragma clang module import Darwin.C.stdbool             /* clang -E: implicit import for #include <stdbool.h> */
#pragma clang module import Darwin.C.time                /* clang -E: implicit import for #include <time.h> */
#pragma clang module import Darwin.POSIX.pthread.pthread /* clang -E: implicit import for #include <pthread.h> */
# 1 "/Users/bbarrows/Downloads/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.0.sdk/usr/include/assert.h" 1 3 4
# 42 "/Users/bbarrows/Downloads/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.0.sdk/usr/include/assert.h" 3 4
#pragma clang module import Darwin.cdefs /* clang -E: implicit import for #include <sys/cdefs.h> */
# 76 "/Users/bbarrows/Downloads/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator13.0.sdk/usr/include/assert.h" 3 4
void __assert_rtn(const char *, const char *, int, const char *) __attribute__((__noreturn__)) __attribute__((__cold__)) __attribute__((__disable_tail_calls__));
# 8 "/Users/bbarrows/repos/ish2/util/timer.h" 2

static inline struct timespec timespec_now(clockid_t clockid)
{
    (__builtin_expect(!(clockid == _CLOCK_MONOTONIC || clockid == _CLOCK_REALTIME), 0) ? __assert_rtn(__func__, "/Users/bbarrows/repos/ish2/util/timer.h", 11, "clockid == CLOCK_MONOTONIC || clockid == CLOCK_REALTIME") : (void)0);
    struct timespec now;
    clock_gettime(clockid, &now);
    return now;
}

static inline struct timespec timespec_add(struct timespec x, struct timespec y)
{
    x.tv_sec += y.tv_sec;
    x.tv_nsec += y.tv_nsec;
    if (x.tv_nsec >= 1000000000)
    {
        x.tv_nsec -= 1000000000;
        x.tv_sec++;
    }
    return x;
}

static inline struct timespec timespec_subtract(struct timespec x, struct timespec y)
{
    struct timespec result;
    if (x.tv_nsec < y.tv_nsec)
    {
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
struct timer
{
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

struct timer *timer_new(clockid_t clockid, timer_callback_t callback, void *data);
void timer_free(struct timer *timer);

struct timer_spec
{
    struct timespec value;
    struct timespec interval;
};
int timer_set(struct timer *timer, struct timer_spec spec, struct timer_spec *oldspec);
# 13 "/Users/bbarrows/repos/ish2/kernel/task.h" 2

struct task
{
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

    struct vfork_info
    {
        _Bool done;
        cond_t cond;
        lock_t lock;
    } * vfork;
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

struct task *task_create_(struct task *parent);

void task_destroy(struct task *task);

void vfork_notify(struct task *task);
pid_t_ task_setsid(struct task *task);
void task_leave_session(struct task *task);

struct tgroup
{
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

struct pid
{
    dword_t id;
    struct task *task;
    struct list session;
    struct list pgroup;
};

extern lock_t pids_lock;

struct pid *pid_get(dword_t pid);
struct task *pid_get_task(dword_t pid);
struct task *pid_get_task_zombie(dword_t id);

extern void (*task_run_hook)(void);

void task_start(struct task *task);

extern void (*exit_hook)(struct task *task, int code);
# 5 "/Users/bbarrows/repos/ish2/kernel/calls.h" 2
# 1 "/Users/bbarrows/repos/ish2/kernel/errno.h" 1

#pragma clang module import Darwin.C.errno /* clang -E: implicit import for #include <errno.h> */
# 116 "/Users/bbarrows/repos/ish2/kernel/errno.h"
int err_map(int err);
int errno_map(void);
# 6 "/Users/bbarrows/repos/ish2/kernel/calls.h" 2

# 1 "/Users/bbarrows/repos/ish2/fs/sock.h" 1

#pragma clang module import Darwin.POSIX.sys.socket  /* clang -E: implicit import for #include <sys/socket.h> */
#pragma clang module import Darwin.POSIX.netinet.in  /* clang -E: implicit import for #include <netinet/in.h> */
#pragma clang module import Darwin.POSIX.netinet.tcp /* clang -E: implicit import for #include <netinet/tcp.h> */

int_t sys_socketcall(dword_t call_num, addr_t args_addr);

int_t sys_socket(dword_t domain, dword_t type, dword_t protocol);
int_t sys_bind(fd_t sock_fd, addr_t sockaddr_addr, uint_t sockaddr_len);
int_t sys_connect(fd_t sock_fd, addr_t sockaddr_addr, uint_t sockaddr_len);
int_t sys_listen(fd_t sock_fd, int_t backlog);
int_t sys_accept(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);
int_t sys_getsockname(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);
int_t sys_getpeername(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);
int_t sys_socketpair(dword_t domain, dword_t type, dword_t protocol, addr_t sockets_addr);
int_t sys_sendto(fd_t sock_fd, addr_t buffer_addr, dword_t len, dword_t flags, addr_t sockaddr_addr, dword_t sockaddr_len);
int_t sys_recvfrom(fd_t sock_fd, addr_t buffer_addr, dword_t len, dword_t flags, addr_t sockaddr_addr, addr_t sockaddr_len_addr);
int_t sys_shutdown(fd_t sock_fd, dword_t how);
int_t sys_setsockopt(fd_t sock_fd, dword_t level, dword_t option, addr_t value_addr, dword_t value_len);
int_t sys_getsockopt(fd_t sock_fd, dword_t level, dword_t option, addr_t value_addr, dword_t len_addr);
int_t sys_sendmsg(fd_t sock_fd, addr_t msghdr_addr, int_t flags);
int_t sys_recvmsg(fd_t sock_fd, addr_t msghdr_addr, int_t flags);
int_t sys_sendmmsg(fd_t sock_fd, addr_t msgvec_addr, uint_t msgvec_len, int_t flags);

struct sockaddr_
{
    uint16_t family;
    char data[14];
};
struct sockaddr_max_
{
    uint16_t family;
    char data[108];
};

size_t sockaddr_size(void *p);

struct sockaddr *sockaddr_to_real(void *p);

struct msghdr_
{
    addr_t msg_name;
    uint_t msg_namelen;
    addr_t msg_iov;
    uint_t msg_iovlen;
    addr_t msg_control;
    uint_t msg_controllen;
    int_t msg_flags;
};

struct cmsghdr_
{
    dword_t len;
    int_t level;
    int_t type;
    uint8_t data[];
};
# 68 "/Users/bbarrows/repos/ish2/fs/sock.h"
struct scm
{
    struct list queue;
    unsigned num_fds;
    struct fd *fds[];
};

static inline int sock_family_to_real(int fake)
{
    switch (fake)
    {
    case 1:
        return 1;
    case 2:
        return 2;
    case 10:
        return 30;
    }
    return -1;
}
static inline int sock_family_from_real(int fake)
{
    switch (fake)
    {
    case 1:
        return 1;
    case 2:
        return 2;
    case 30:
        return 10;
    }
    return -1;
}

static inline int sock_type_to_real(int type, int protocol)
{
    switch (type & 0xff)
    {
    case 1:
        if (protocol != 0 && protocol != 6)
            return -1;
        return 1;
    case 2:
        switch (protocol)
        {
        default:
            return -1;
        case 0:
        case 17:
        case 1:
        case 58:
            break;
        }
        return 2;
    case 3:
        switch (protocol)
        {
        default:
            return -1;
        case 255:
        case 17:
        case 1:
        case 58:
            break;
        }
        return 2;
    }
    return -1;
}
# 143 "/Users/bbarrows/repos/ish2/fs/sock.h"
static inline int sock_flags_to_real(int fake)
{
    int real = 0;
    if (fake & 0x1)
        real |= 0x1;
    if (fake & 0x2)
        real |= 0x2;
    if (fake & 0x8)
        real |= 0x20;
    if (fake & 0x20)
        real |= 0x10;
    if (fake & 0x40)
        real |= 0x80;
    if (fake & 0x80)
        real |= 0x8;
    if (fake & 0x100)
        real |= 0x40;
    if (fake & ~(0x1 | 0x2 | 0x8 | 0x20 | 0x40 | 0x80 | 0x100))
        __use(0, fake);
    return real;
}
static inline int sock_flags_from_real(int real)
{
    int fake = 0;
    if (real & 0x1)
        fake |= 0x1;
    if (real & 0x2)
        fake |= 0x2;
    if (real & 0x20)
        fake |= 0x8;
    if (real & 0x10)
        fake |= 0x20;
    if (real & 0x80)
        fake |= 0x40;
    if (real & 0x8)
        fake |= 0x80;
    if (real & 0x40)
        fake |= 0x100;
    if (real & ~(0x1 | 0x2 | 0x20 | 0x10 | 0x80 | 0x8 | 0x40))
        __use(0, real);
    return fake;
}
# 200 "/Users/bbarrows/repos/ish2/fs/sock.h"
static inline int sock_opt_to_real(int fake, int level)
{
    switch (level)
    {
    case 1:
        switch (fake)
        {
        case 2:
            return 0x0004;
        case 3:
            return 0x1008;
        case 4:
            return 0x1007;
        case 6:
            return 0x0020;
        case 9:
            return 0x0008;
        case 13:
            return 0x0080;
        case 7:
            return 0x1001;
        case 8:
            return 0x1002;
        case 29:
            return 0x0400;
        }
        break;
    case 6:
        switch (fake)
        {
        case 1:
            return 0x01;
        case 9:
            return 0;
        }
        break;
    case 0:
        switch (fake)
        {
        case 1:
            return 3;
        case 2:
            return 4;
        case 3:
            return 2;
        case 7:
            return 8;
        case 12:
            return 24;
        case 13:
            return 27;
        }
        break;
    case 41:
        switch (fake)
        {
        case 16:
            return 4;
        case 67:
            return 36;
        case 26:
            return 27;
        }
        break;
    }
    return -1;
}

static inline int sock_level_to_real(int fake)
{
    if (fake == 1)
        return 0xffff;
    return fake;
}

extern const char *sock_tmp_prefix;

struct tcp_info_
{
    uint8_t state;
    uint8_t ca_state;
    uint8_t retransmits;
    uint8_t probes;
    uint8_t backoff;
    uint8_t options;
    uint8_t snd_wscale : 4, rcv_wscale : 4;

    uint32_t rto;
    uint32_t ato;
    uint32_t snd_mss;
    uint32_t rcv_mss;

    uint32_t unacked;
    uint32_t sacked;
    uint32_t lost;
    uint32_t retrans;
    uint32_t fackets;

    uint32_t last_data_sent;
    uint32_t last_ack_sent;
    uint32_t last_data_recv;
    uint32_t last_ack_recv;

    uint32_t pmtu;
    uint32_t rcv_ssthresh;
    uint32_t rtt;
    uint32_t rttvar;
    uint32_t snd_ssthresh;
    uint32_t snd_cwnd;
    uint32_t advmss;
    uint32_t reordering;

    uint32_t rcv_rtt;
    uint32_t rcv_space;

    uint32_t total_retrans;
};
# 13 "/Users/bbarrows/repos/ish2/kernel/calls.h" 2

void handle_interrupt(int interrupt);

int __attribute__((warn_unused_result)) user_read(addr_t addr, void *buf, size_t count);
int __attribute__((warn_unused_result)) user_write(addr_t addr, const void *buf, size_t count);
int __attribute__((warn_unused_result)) user_read_task(struct task *task, addr_t addr, void *buf, size_t count);
int __attribute__((warn_unused_result)) user_write_task(struct task *task, addr_t addr, const void *buf, size_t count);
int __attribute__((warn_unused_result)) user_read_string(addr_t addr, char *buf, size_t max);
int __attribute__((warn_unused_result)) user_write_string(addr_t addr, const char *buf);

dword_t sys_clone(dword_t flags, addr_t stack, addr_t ptid, addr_t tls, addr_t ctid);
dword_t sys_fork(void);
dword_t sys_vfork(void);
dword_t sys_execve(addr_t file, addr_t argv, addr_t envp);
int do_execve(const char *file, size_t argc, const char *argv, const char *envp);
dword_t sys_exit(dword_t status);
_Noreturn void do_exit(int status);
_Noreturn void do_exit_group(int status);
dword_t sys_exit_group(dword_t status);
dword_t sys_wait4(pid_t_ pid, addr_t status_addr, dword_t options, addr_t rusage_addr);
dword_t sys_waitpid(pid_t_ pid, addr_t status_addr, dword_t options);

addr_t sys_brk(addr_t new_brk);

addr_t sys_mmap(addr_t args_addr);
addr_t sys_mmap2(addr_t addr, dword_t len, dword_t prot, dword_t flags, fd_t fd_no, dword_t offset);
int_t sys_munmap(addr_t addr, uint_t len);
int_t sys_mprotect(addr_t addr, uint_t len, int_t prot);
int_t sys_mremap(addr_t addr, dword_t old_len, dword_t new_len, dword_t flags);
dword_t sys_madvise(addr_t addr, dword_t len, dword_t advice);
dword_t sys_mbind(addr_t addr, dword_t len, int_t mode, addr_t nodemask, dword_t maxnode, uint_t flags);
int_t sys_mlock(addr_t addr, dword_t len);
int_t sys_msync(addr_t addr, dword_t len, int_t flags);

struct iovec_
{
    addr_t base;
    uint_t len;
};
dword_t sys_read(fd_t fd_no, addr_t buf_addr, dword_t size);
dword_t sys_readv(fd_t fd_no, addr_t iovec_addr, dword_t iovec_count);
dword_t sys_write(fd_t fd_no, addr_t buf_addr, dword_t size);
dword_t sys_writev(fd_t fd_no, addr_t iovec_addr, dword_t iovec_count);
dword_t sys__llseek(fd_t f, dword_t off_high, dword_t off_low, addr_t res_addr, dword_t whence);
dword_t sys_lseek(fd_t f, dword_t off, dword_t whence);
dword_t sys_pread(fd_t f, addr_t buf_addr, dword_t buf_size, off_t_ off);
dword_t sys_pwrite(fd_t f, addr_t buf_addr, dword_t size, off_t_ off);
dword_t sys_ioctl(fd_t f, dword_t cmd, dword_t arg);
dword_t sys_fcntl(fd_t f, dword_t cmd, dword_t arg);
dword_t sys_fcntl32(fd_t fd, dword_t cmd, dword_t arg);
dword_t sys_dup(fd_t fd);
dword_t sys_dup2(fd_t fd, fd_t new_fd);
dword_t sys_dup3(fd_t f, fd_t new_f, int_t flags);
dword_t sys_close(fd_t fd);
dword_t sys_fsync(fd_t f);
dword_t sys_flock(fd_t fd, dword_t operation);
int_t sys_pipe(addr_t pipe_addr);
int_t sys_pipe2(addr_t pipe_addr, int_t flags);
struct pollfd_
{
    fd_t fd;
    word_t events;
    word_t revents;
};
dword_t sys_poll(addr_t fds, dword_t nfds, int_t timeout);
dword_t sys_select(fd_t nfds, addr_t readfds_addr, addr_t writefds_addr, addr_t exceptfds_addr, addr_t timeout_addr);
dword_t sys_pselect(fd_t nfds, addr_t readfds_addr, addr_t writefds_addr, addr_t exceptfds_addr, addr_t timeout_addr, addr_t sigmask_addr);
dword_t sys_ppoll(addr_t fds, dword_t nfds, addr_t timeout_addr, addr_t sigmask_addr, dword_t sigsetsize);
fd_t sys_epoll_create(int_t flags);
fd_t sys_epoll_create0(void);
int_t sys_epoll_ctl(fd_t epoll, int_t op, fd_t fd, addr_t event_addr);
int_t sys_epoll_wait(fd_t epoll, addr_t events_addr, int_t max_events, int_t timeout);
int_t sys_epoll_pwait(fd_t epoll_f, addr_t events_addr, int_t max_events, int_t timeout, addr_t sigmask_addr, dword_t sigsetsize);

int_t sys_eventfd2(uint_t initval, int_t flags);
int_t sys_eventfd(uint_t initval);

fd_t sys_open(addr_t path_addr, dword_t flags, mode_t_ mode);
fd_t sys_openat(fd_t at, addr_t path_addr, dword_t flags, mode_t_ mode);
dword_t sys_close(fd_t fd);
dword_t sys_link(addr_t src_addr, addr_t dst_addr);
dword_t sys_linkat(fd_t src_at_f, addr_t src_addr, fd_t dst_at_f, addr_t dst_addr);
dword_t sys_unlink(addr_t path_addr);
dword_t sys_unlinkat(fd_t at_f, addr_t path_addr, int_t flags);
dword_t sys_rmdir(addr_t path_addr);
dword_t sys_rename(addr_t src_addr, addr_t dst_addr);
dword_t sys_renameat(fd_t src_at_f, addr_t src_addr, fd_t dst_at_f, addr_t dst_addr);
dword_t sys_renameat2(fd_t src_at_f, addr_t src_addr, fd_t dst_at_f, addr_t dst_addr, int_t flags);
dword_t sys_symlink(addr_t target_addr, addr_t link_addr);
dword_t sys_symlinkat(addr_t target_addr, fd_t at_f, addr_t link_addr);
dword_t sys_mknod(addr_t path_addr, mode_t_ mode, dev_t_ dev);
dword_t sys_mknodat(fd_t at_f, addr_t path_addr, mode_t_ mode, dev_t_ dev);
dword_t sys_access(addr_t path_addr, dword_t mode);
dword_t sys_faccessat(fd_t at_f, addr_t path, mode_t_ mode, dword_t flags);
dword_t sys_readlink(addr_t path, addr_t buf, dword_t bufsize);
dword_t sys_readlinkat(fd_t at_f, addr_t path, addr_t buf, dword_t bufsize);
int_t sys_getdents(fd_t f, addr_t dirents, dword_t count);
int_t sys_getdents64(fd_t f, addr_t dirents, dword_t count);
dword_t sys_stat64(addr_t path_addr, addr_t statbuf_addr);
dword_t sys_lstat64(addr_t path_addr, addr_t statbuf_addr);
dword_t sys_fstat64(fd_t fd_no, addr_t statbuf_addr);
dword_t sys_fstatat64(fd_t at, addr_t path_addr, addr_t statbuf_addr, dword_t flags);
dword_t sys_fchmod(fd_t f, dword_t mode);
dword_t sys_fchmodat(fd_t at_f, addr_t path_addr, dword_t mode);
dword_t sys_chmod(addr_t path_addr, dword_t mode);
dword_t sys_fchown32(fd_t f, dword_t owner, dword_t group);
dword_t sys_fchownat(fd_t at_f, addr_t path_addr, dword_t owner, dword_t group, int flags);
dword_t sys_chown32(addr_t path_addr, uid_t_ owner, uid_t_ group);
dword_t sys_lchown(addr_t path_addr, uid_t_ owner, uid_t_ group);
dword_t sys_truncate64(addr_t path_addr, dword_t size_low, dword_t size_high);
dword_t sys_ftruncate64(fd_t f, dword_t size_low, dword_t size_high);
dword_t sys_fallocate(fd_t f, dword_t mode, dword_t offset_low, dword_t offset_high, dword_t len_low, dword_t len_high);
dword_t sys_mkdir(addr_t path_addr, mode_t_ mode);
dword_t sys_mkdirat(fd_t at_f, addr_t path_addr, mode_t_ mode);
dword_t sys_utimensat(fd_t at_f, addr_t path_addr, addr_t times_addr, dword_t flags);
dword_t sys_utimes(addr_t path_addr, addr_t times_addr);
dword_t sys_utime(addr_t path_addr, addr_t times_addr);
dword_t sys_times(addr_t tbuf);
dword_t sys_umask(dword_t mask);

dword_t sys_sendfile(fd_t out_fd, fd_t in_fd, addr_t offset_addr, dword_t count);
dword_t sys_sendfile64(fd_t out_fd, fd_t in_fd, addr_t offset_addr, dword_t count);
dword_t sys_copy_file_range(fd_t in_fd, addr_t in_off, fd_t out_fd, addr_t out_off, dword_t len, uint_t flags);

dword_t sys_statfs(addr_t path_addr, addr_t buf_addr);
dword_t sys_statfs64(addr_t path_addr, dword_t buf_size, addr_t buf_addr);
dword_t sys_fstatfs(fd_t f, addr_t buf_addr);
dword_t sys_fstatfs64(fd_t f, addr_t buf_addr);

dword_t sys_mount(addr_t source_addr, addr_t target_addr, addr_t type_addr, dword_t flags, addr_t data_addr);
dword_t sys_umount2(addr_t target_addr, dword_t flags);

dword_t sys_xattr_stub(addr_t path_addr, addr_t name_addr, addr_t value_addr, dword_t size, dword_t flags);

pid_t_ sys_getpid(void);
pid_t_ sys_gettid(void);
pid_t_ sys_getppid(void);
pid_t_ sys_getpgid(pid_t_ pid);
dword_t sys_setpgid(pid_t_ pid, pid_t_ pgid);
pid_t_ sys_getpgrp(void);
dword_t sys_setpgrp(void);
uid_t_ sys_getuid32(void);
uid_t_ sys_getuid(void);
int_t sys_setuid(uid_t uid);
uid_t_ sys_geteuid32(void);
uid_t_ sys_geteuid(void);
int_t sys_setgid(uid_t gid);
uid_t_ sys_getgid32(void);
uid_t_ sys_getgid(void);
uid_t_ sys_getegid32(void);
uid_t_ sys_getegid(void);
dword_t sys_setresuid(uid_t_ ruid, uid_t_ euid, uid_t_ suid);
dword_t sys_setresgid(uid_t_ rgid, uid_t_ egid, uid_t_ sgid);
int_t sys_getresuid(addr_t ruid_addr, addr_t euid_addr, addr_t suid_addr);
int_t sys_getresgid(addr_t rgid_addr, addr_t egid_addr, addr_t sgid_addr);
int_t sys_getgroups(dword_t size, addr_t list);
int_t sys_setgroups(dword_t size, addr_t list);
int_t sys_capget(addr_t header_addr, addr_t data_addr);
int_t sys_capset(addr_t header_addr, addr_t data_addr);
dword_t sys_getcwd(addr_t buf_addr, dword_t size);
dword_t sys_chdir(addr_t path_addr);
dword_t sys_chroot(addr_t path_addr);
dword_t sys_fchdir(fd_t f);
int_t sys_personality(dword_t pers);
int task_set_thread_area(struct task *task, addr_t u_info);
int sys_set_thread_area(addr_t u_info);
int sys_set_tid_address(addr_t blahblahblah);
dword_t sys_setsid(void);
dword_t sys_getsid(void);

int_t sys_sched_yield(void);
int_t sys_prctl(dword_t option, uint_t arg2, uint_t arg3, uint_t arg4, uint_t arg5);
int_t sys_arch_prctl(int_t code, addr_t addr);
int_t sys_reboot(int_t magic, int_t magic2, int_t cmd);

struct uname
{
    char system[65];
    char hostname[65];
    char release[65];
    char version[65];
    char arch[65];
    char domain[65];
};
void do_uname(struct uname *uts);
dword_t sys_uname(addr_t uts_addr);
dword_t sys_sethostname(addr_t hostname_addr, dword_t hostname_len);

struct sys_info
{
    dword_t uptime;
    dword_t loads[3];
    dword_t totalram;
    dword_t freeram;
    dword_t sharedram;
    dword_t bufferram;
    dword_t totalswap;
    dword_t freeswap;
    word_t procs;
    dword_t totalhigh;
    dword_t freehigh;
    dword_t mem_unit;
    char pad;
};
dword_t sys_sysinfo(addr_t info_addr);

dword_t sys_futex(addr_t uaddr, dword_t op, dword_t val, addr_t timeout_or_val2, addr_t uaddr2, dword_t val3);
int_t sys_set_robust_list(addr_t robust_list, dword_t len);
int_t sys_get_robust_list(pid_t_ pid, addr_t robust_list_ptr, addr_t len_ptr);

dword_t sys_getrandom(addr_t buf_addr, dword_t len, dword_t flags);
int_t sys_syslog(int_t type, addr_t buf_addr, int_t len);
int_t sys_ipc(uint_t call, int_t first, int_t second, int_t third, addr_t ptr, int_t fifth);

typedef int (*syscall_t)(dword_t, dword_t, dword_t, dword_t, dword_t, dword_t);
# 10 "/Users/bbarrows/repos/ish2/emu/interp.c" 2

#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wtautological-constant-out-of-range-compare"
# 47 "/Users/bbarrows/repos/ish2/emu/interp.c"
static _Bool modrm_compute(struct cpu_state *cpu, struct tlb *tlb, addr_t *addr_out,
                           struct modrm *modrm, struct regptr *modrm_regptr, struct regptr *modrm_base);
# 588 "/Users/bbarrows/repos/ish2/emu/interp.c"
# 1 "/Users/bbarrows/repos/ish2/emu/interp/fpu.h" 1

# 1 "/Users/bbarrows/repos/ish2/emu/fpu.h" 1

struct cpu_state;
struct fpu_env32;
struct fpu_state32;

typedef float float32;
typedef double float64;

enum fpu_const
{
    fconst_one = 0,
    fconst_log2t = 1,
    fconst_log2e = 2,
    fconst_pi = 3,
    fconst_log2 = 4,
    fconst_ln2 = 5,
    fconst_zero = 6,
};
static float80 fpu_consts[] = {
    [fconst_one] = (float80){.signif = 0x8000000000000000, .signExp = 0x3fff},
    [fconst_log2t] = (float80){.signif = 0xd49a784bcd1b8afe, .signExp = 0x4000},
    [fconst_log2e] = (float80){.signif = 0xb8aa3b295c17f0bc, .signExp = 0x3fff},
    [fconst_pi] = (float80){.signif = 0xc90fdaa22168c235, .signExp = 0x4000},
    [fconst_log2] = (float80){.signif = 0x9a209a84fbcff799, .signExp = 0x3ffd},
    [fconst_ln2] = (float80){.signif = 0xb17217f7d1cf79ac, .signExp = 0x3ffe},
    [fconst_zero] = (float80){.signif = 0x0000000000000000, .signExp = 0x0000},
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
# 3 "/Users/bbarrows/repos/ish2/emu/interp/fpu.h" 2
# 589 "/Users/bbarrows/repos/ish2/emu/interp.c" 2
# 616 "/Users/bbarrows/repos/ish2/emu/interp.c"
extern int current_pid(void);

__attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) int cpu_step32(struct cpu_state *cpu, struct tlb *tlb)
{
    dword_t addr_offset = 0;
    dword_t saved_ip = cpu->eip;
    struct regptr modrm_regptr, modrm_base;
    dword_t addr = 0;
    union xmm_reg xmm_src;
    union xmm_reg xmm_dst;
    float80 ftmp;
    ;
# 631 "/Users/bbarrows/repos/ish2/emu/interp.c"
    byte_t insn;
    uint64_t imm = 0;
    struct modrm modrm;
# 642 "/Users/bbarrows/repos/ish2/emu/interp.c"
restart:

    insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
    cpu->eip += 8 / 8;
    __use(0, insn);

    switch (insn)
    {
# 671 "/Users/bbarrows/repos/ish2/emu/interp.c"
// This is ADD Brad http://ref.x86asm.net/coder32.html#x00
    case 0x00 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
        }
        else
        {
            ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
        }
        else
        {
            ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        *(uint8_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x5:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint32_t)imm);
        cpu->op2 = ((uint32_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->eax)), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->eax)), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        *(uint32_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        }
        else
        {
            ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        }
        else
        {
            ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) | (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->eax = ((uint8_t)cpu->eax) | ((uint8_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)(((uint8_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x5:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->eax = ((uint32_t)cpu->eax) | ((uint32_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)(((uint32_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;

    case 0x0f:

        insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, insn);
        switch (insn)
        {
        case 0x18 ... 0x1f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            break;

        case 0x28:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 0x29:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;

        case 0x2e:

            break;

        case 0x31:

            __use(0);
            imm = ({ uint32_t low, high; __asm__ volatile("rdtsc" : "=a" (high), "=d" (low)); ((uint64_t) high) << 32 | low; });
            cpu->eax = imm & 0xffffffff;
            cpu->edx = imm >> 32;
            break;

        case 0x40:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->of))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x41:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->of))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x42:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->cf))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x43:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->cf))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x44:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x45:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x46:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x47:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x48:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x49:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4a:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4b:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4c:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4d:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4e:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;

        case 0x57:
            __use(0);

            break;

        case 0x6e:
            __use(0);

            break;

        case 0x6f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;

        case 0x73:
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            switch (modrm.opcode)
            {
            case 0x02:
                __use(0);

            default:
            {
                cpu->eip = saved_ip;
                return 6;
            };
            }
            break;

        case 0x77:
            __use(0);
            break;

        case 0x7e:
            __use(0);

            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;

        case 0x7f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;

        case 0x80:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if ((cpu->of))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x81:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (!(cpu->of))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x82:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if ((cpu->cf))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x83:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (!(cpu->cf))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x84:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x85:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x86:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x87:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (!((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x88:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x89:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (!(cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8a:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8b:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (!(cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8c:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8d:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (!((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8e:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8f:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            if (!(((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
            {
                cpu->eip += ((uint32_t)imm);
                if (32 == 16)
                    cpu->eip &= 0xffff;
            };
            break;

        case 0x90:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->of) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->of) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x91:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->of) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->of) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x92:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->cf) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->cf) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x93:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->cf) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->cf) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x94:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->zf_res ? cpu->res == 0 : cpu->zf) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->zf_res ? cpu->res == 0 : cpu->zf) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x95:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->zf_res ? cpu->res == 0 : cpu->zf) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->zf_res ? cpu->res == 0 : cpu->zf) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x96:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x97:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x98:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x99:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9a:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9b:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9c:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = (((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ^ (cpu->of)) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9d:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = (((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ^ (cpu->of)) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9e:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;

        case 0xa2:
            __use(0);
            do_cpuid(&cpu->eax, &cpu->ebx, &cpu->ecx, &cpu->edx);
            break;

        case 0xa3:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32))) ? 1 : 0;
            ;
            break;

        case 0xa4:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            if (((uint8_t)imm) % 32 != 0)
            {
                int cnt = ((uint8_t)imm) % 32;
                cpu->res = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) >> (32 - cnt);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            };
            break;
        case 0xa5:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (((uint8_t)cpu->ecx) % 32 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 32;
                cpu->res = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) >> (32 - cnt);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            };
            break;

        case 0xab:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32))) ? 1 : 0;
            ;
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32));
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;

        case 0xac:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            if (((uint8_t)imm) % 32 != 0)
            {
                int cnt = ((uint8_t)imm) % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->res = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) << (32 - cnt);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            };
            break;
        case 0xad:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (((uint8_t)cpu->ecx) % 32 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->res = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) << (32 - cnt);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            };
            break;

        case 0xaf:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = cpu->of = ({ int ov = __builtin_mul_overflow((int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;

        case 0xb0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = ((uint8_t)cpu->eax);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
            {
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                }
                else
                {
                    ({ uint8_t _val = (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
            }
            else
                *(uint8_t *)&cpu->eax = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0xb1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = ((uint32_t)cpu->eax);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) cpu->eax)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) cpu->eax)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
            {
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
                }
                else
                {
                    ({ uint32_t _val = (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
            }
            else
                *(uint32_t *)&cpu->eax = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;

        case 0xb3:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32))) ? 1 : 0;
            ;
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32));
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;

        case 0xb6:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0xb7:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
# 868 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0xba:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            switch (modrm.opcode)
            {
            case 4:
                __use(0);
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + ((uint32_t) imm) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint32_t) imm) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint32_t)imm) % 32))) ? 1 : 0;
                ;
                break;
            case 5:
                __use(0);
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + ((uint32_t) imm) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint32_t) imm) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint32_t)imm) % 32))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << (((uint32_t)imm) % 32));
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << (((uint32_t) imm) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            case 6:
                __use(0);
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + ((uint32_t) imm) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint32_t) imm) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint32_t)imm) % 32))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << (((uint32_t)imm) % 32));
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << (((uint32_t) imm) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            case 7:
                __use(0);
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + ((uint32_t) imm) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint32_t) imm) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint32_t)imm) % 32))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << (((uint32_t)imm) % 32));
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << (((uint32_t) imm) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            default:
            {
                cpu->eip = saved_ip;
                return 6;
            };
            };
            break;

        case 0xbb:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32))) ? 1 : 0;
            ;
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32));
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0xbc:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->zf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0;
            cpu->zf_res = 0;
            if (!cpu->zf)
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = __builtin_ctz((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            break;
        case 0xbd:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->zf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0;
            cpu->zf_res = 0;
            if (!cpu->zf)
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = 32 - __builtin_clz((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            break;

        case 0xbe:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (uint32_t)(int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0xbf:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (uint32_t)(int16_t)(modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;

        case 0xc0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            do
            {
                dword_t tmp = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = tmp;
                }
                else
                {
                    ({ uint8_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
            } while (0);
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0xc1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            do
            {
                dword_t tmp = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
                (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = tmp;
                }
                else
                {
                    ({ uint32_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
            } while (0);
            cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
# 897 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0xc8:
            __use(0);
            *(uint32_t *)&cpu->eax = __builtin_bswap32(((uint32_t)cpu->eax));
            break;
        case 0xc9:
            __use(0);
            *(uint32_t *)&cpu->ecx = __builtin_bswap32(((uint32_t)cpu->ecx));
            break;
        case 0xca:
            __use(0);
            *(uint32_t *)&cpu->edx = __builtin_bswap32(((uint32_t)cpu->edx));
            break;
        case 0xcb:
            __use(0);
            *(uint32_t *)&cpu->ebx = __builtin_bswap32(((uint32_t)cpu->ebx));
            break;
        case 0xcc:
            __use(0);
            *(uint32_t *)&cpu->esp = __builtin_bswap32(((uint32_t)cpu->esp));
            break;
        case 0xcd:
            __use(0);
            *(uint32_t *)&cpu->ebp = __builtin_bswap32(((uint32_t)cpu->ebp));
            break;
        case 0xce:
            __use(0);
            *(uint32_t *)&cpu->esi = __builtin_bswap32(((uint32_t)cpu->esi));
            break;
        case 0xcf:
            __use(0);
            *(uint32_t *)&cpu->edi = __builtin_bswap32(((uint32_t)cpu->edi));
            break;
# 921 "/Users/bbarrows/repos/ish2/emu/interp.c"
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        }
        break;

    case 0x10 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == (uint8_t)-1);
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
        }
        else
        {
            ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) == ((uint32_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) == (uint32_t)-1);
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
        }
        else
        {
            ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == (uint8_t)-1);
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == ((uint32_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == (uint32_t)-1);
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
        *(uint8_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x5:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint32_t)imm);
        cpu->op2 = ((uint32_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->eax)), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->eax)), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
        *(uint32_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == (uint8_t)-1);
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
        }
        else
        {
            ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) == ((uint32_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) == (uint32_t)-1);
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
        }
        else
        {
            ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == (uint8_t)-1);
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == ((uint32_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == (uint32_t)-1);
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
        *(uint8_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x5:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint32_t)imm);
        cpu->op2 = ((uint32_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->eax)), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->eax)), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
        *(uint32_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        }
        else
        {
            ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        }
        else
        {
            ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) & (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) & (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->eax = ((uint8_t)cpu->eax) & ((uint8_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)(((uint8_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x5:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->eax = ((uint32_t)cpu->eax) & ((uint32_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)(((uint32_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
        }
        else
        {
            ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
        }
        else
        {
            ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        *(uint8_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x5:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint32_t)imm);
        cpu->op2 = ((uint32_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->eax)), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->eax)), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        *(uint32_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;

    case 0x2e:
        __use(0);
        goto restart;

    case 0x30 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        }
        else
        {
            ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        }
        else
        {
            ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) ^ (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) ^ (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->eax = ((uint8_t)cpu->eax) ^ ((uint8_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)(((uint8_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x5:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->eax = ((uint32_t)cpu->eax) ^ ((uint32_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int32_t)(((uint32_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x5:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint32_t)imm);
        cpu->op2 = ((uint32_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->eax)), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->eax)), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;

    case 0x3e:
        __use(0);
        goto restart;

    case 0x40:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->eax);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->eax)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->eax)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->eax = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x41:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->ecx);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->ecx)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->ecx)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->ecx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x42:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->edx);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->edx)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->edx)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->edx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x43:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->ebx);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->ebx)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->ebx)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->ebx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x44:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->esp);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->esp)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->esp)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->esp = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x45:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->ebp);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->ebp)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->ebp)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->ebp = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x46:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->esi);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->esi)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->esi)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->esi = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x47:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->edi);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) (((uint32_t) cpu->edi)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) (((uint32_t) cpu->edi)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->edi = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x48:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->eax);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->eax)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->eax)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->eax = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x49:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->ecx);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->ecx)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->ecx)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->ecx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4a:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->edx);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->edx)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->edx)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->edx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4b:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->ebx);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->ebx)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->ebx)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->ebx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4c:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->esp);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->esp)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->esp)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->esp = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4d:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->ebp);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->ebp)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->ebp)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->ebp = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4e:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->esi);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->esi)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->esi)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->esi = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4f:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint32_t)cpu->edi);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (((uint32_t) cpu->edi)), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (((uint32_t) cpu->edi)), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            *(uint32_t *)&cpu->edi = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;

    case 0x50:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->eax); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x51:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->ecx); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x52:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->edx); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x53:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->ebx); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x54:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->esp); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x55:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->ebp); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x56:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->esi); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x57:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->edi); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;

    case 0x58:
        __use(0);
        *(uint32_t *)&cpu->eax = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;
    case 0x59:
        __use(0);
        *(uint32_t *)&cpu->ecx = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;
    case 0x5a:
        __use(0);
        *(uint32_t *)&cpu->edx = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;
    case 0x5b:
        __use(0);
        *(uint32_t *)&cpu->ebx = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;
    case 0x5c:
        __use(0);
        *(uint32_t *)&cpu->esp = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;
    case 0x5d:
        __use(0);
        *(uint32_t *)&cpu->ebp = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;
    case 0x5e:
        __use(0);
        *(uint32_t *)&cpu->esi = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;
    case 0x5f:
        __use(0);
        *(uint32_t *)&cpu->edi = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;

    case 0x65:
        __use(0);
        addr += cpu->tls_ptr;
        goto restart;

    case 0x60:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->eax); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        ({ uint32_t _val = ((uint32_t) cpu->ecx); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        ({ uint32_t _val = ((uint32_t) cpu->edx); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        ({ uint32_t _val = ((uint32_t) cpu->ebx); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        ({ uint32_t _val = ((uint32_t) cpu->esp); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        ({ uint32_t _val = ((uint32_t) cpu->ebp); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        ({ uint32_t _val = ((uint32_t) cpu->esi); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        ({ uint32_t _val = ((uint32_t) cpu->edi); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x61:
        __use(0);
        *(uint32_t *)&cpu->edi = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        *(uint32_t *)&cpu->esi = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;

        *(uint32_t *)&cpu->ebp = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        *(uint32_t *)&cpu->ebx = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        *(uint32_t *)&cpu->ebx = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        *(uint32_t *)&cpu->edx = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        *(uint32_t *)&cpu->ecx = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        *(uint32_t *)&cpu->eax = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;

    case 0x66:

        __use(0);
        return cpu_step16(cpu, tlb);

    case 0x67:
        __use(0);
        goto restart;

    case 0x68:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        ({ uint32_t _val = ((uint32_t) imm); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x69:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        cpu->cf = cpu->of = ({ int ov = __builtin_mul_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = cpu->res;
        cpu->pf_res = 1;
        cpu->zf = cpu->sf = cpu->zf_res = cpu->sf_res = 0;
        break;
    case 0x6a:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        ({ uint32_t _val = ((uint32_t) imm); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x6b:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->cf = cpu->of = ({ int ov = __builtin_mul_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = cpu->res;
        cpu->pf_res = 1;
        cpu->zf = cpu->sf = cpu->zf_res = cpu->sf_res = 0;
        break;

    case 0x70:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->of))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x71:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->of))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x72:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->cf))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x73:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->cf))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x74:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x75:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x76:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x77:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x78:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x79:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7a:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7b:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7c:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7d:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7e:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7f:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;
# 1064 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0x80:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 1:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint8_t)imm);
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 2:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 3:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 4:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t)imm);
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 5:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 6:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint8_t)imm);
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 7:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;
    case 0x81:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 1:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint32_t)imm);
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 2:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 3:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 4:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t)imm);
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 5:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 6:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint32_t)imm);
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 7:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;
    case 0x83:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 1:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint32_t)imm);
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 2:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 3:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 4:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t)imm);
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 5:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 6:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint32_t)imm);
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 7:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;

    case 0x84:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        break;
    case 0x85:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        break;

    case 0x86:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        do
        {
            dword_t tmp = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = tmp;
            }
            else
            {
                ({ uint8_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
        } while (0);
        break;
    case 0x87:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        do
        {
            dword_t tmp = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = tmp;
            }
            else
            {
                ({ uint32_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
        } while (0);
        break;

    case 0x88:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        }
        else
        {
            ({ uint8_t _val = (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;
    case 0x89:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
        }
        else
        {
            ({ uint32_t _val = (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;
    case 0x8a:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        break;
    case 0x8b:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        break;

    case 0x8d:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            cpu->eip = saved_ip;
            return 6;
        };
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = addr;
        break;

    case 0x8c:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.reg != reg_ebp)
        {
            cpu->eip = saved_ip;
            return 6;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->gs;
        }
        else
        {
            ({ uint16_t _val = cpu->gs; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;
    case 0x8e:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.reg != reg_ebp)
        {
            cpu->eip = saved_ip;
            return 6;
        };
        cpu->gs = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        break;

    case 0x8f:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        }
        else
        {
            ({ uint32_t _val = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; }); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->esp += 32 / 8;
        break;

    case 0x90:
        __use(0);
        break;
    case 0x91:
        __use(0);
        do
        {
            dword_t tmp = ((uint32_t)cpu->ecx);
            *(uint32_t *)&cpu->ecx = ((uint32_t)cpu->eax);
            *(uint32_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x92:
        __use(0);
        do
        {
            dword_t tmp = ((uint32_t)cpu->edx);
            *(uint32_t *)&cpu->edx = ((uint32_t)cpu->eax);
            *(uint32_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x93:
        __use(0);
        do
        {
            dword_t tmp = ((uint32_t)cpu->ebx);
            *(uint32_t *)&cpu->ebx = ((uint32_t)cpu->eax);
            *(uint32_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x94:
        __use(0);
        do
        {
            dword_t tmp = ((uint32_t)cpu->esp);
            *(uint32_t *)&cpu->esp = ((uint32_t)cpu->eax);
            *(uint32_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x95:
        __use(0);
        do
        {
            dword_t tmp = ((uint32_t)cpu->ebp);
            *(uint32_t *)&cpu->ebp = ((uint32_t)cpu->eax);
            *(uint32_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x96:
        __use(0);
        do
        {
            dword_t tmp = ((uint32_t)cpu->esi);
            *(uint32_t *)&cpu->esi = ((uint32_t)cpu->eax);
            *(uint32_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x97:
        __use(0);
        do
        {
            dword_t tmp = ((uint32_t)cpu->edi);
            *(uint32_t *)&cpu->edi = ((uint32_t)cpu->eax);
            *(uint32_t *)&cpu->eax = tmp;
        } while (0);
        break;

    case 0x98:
        __use(0);
        (*((uint16_t *)(((char *)(cpu)) + __builtin_offsetof(struct cpu_state, eax)))) = (int32_t)(*((uint32_t *)(((char *)(cpu)) + __builtin_offsetof(struct cpu_state, ax))));
        break;
    case 0x99:
        __use(0);
        *(uint32_t *)&cpu->edx = ((uint32_t)cpu->eax) & (1 << (32 - 1)) ? (uint32_t)-1 : 0;
        break;

    case 0x9b:
        __use(0);
        break;

    case 0x9c:
        __use(0);
        collapse_flags(cpu);
        ({ uint32_t _val = cpu->eflags; if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        break;
    case 0x9d:
        __use(0);
        cpu->eflags = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        expand_flags(cpu);
        break;
    case 0x9e:
        __use(0);
        cpu->eflags &= 0xffffff00 | ~0b11010101;
        cpu->eflags |= cpu->ah & 0b11010101;
        expand_flags(cpu);
        break;

    case 0xa0:
        __use(0);
        addr_offset = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)addr_offset);
        addr += addr_offset;
        *(uint8_t *)&cpu->eax = ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; });
        break;
    case 0xa1:
        __use(0);
        addr_offset = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)addr_offset);
        addr += addr_offset;
        *(uint32_t *)&cpu->eax = ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; });
        break;
    case 0xa2:
        __use(0);
        addr_offset = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)addr_offset);
        addr += addr_offset;
        ({ uint8_t _val = ((uint8_t) cpu->eax); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        break;
    case 0xa3:
        __use(0);
        addr_offset = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)addr_offset);
        addr += addr_offset;
        ({ uint32_t _val = ((uint32_t) cpu->eax); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        break;

    case 0xa4:
        __use(0);
        ({ uint8_t _val = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; }); if (!tlb_write(tlb, cpu->edi, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
        if (!cpu->df)
            cpu->esi += 8 / 8;
        else
            cpu->esi -= 8 / 8;
        if (!cpu->df)
            cpu->edi += 8 / 8;
        else
            cpu->edi -= 8 / 8;
        break;
    case 0xa5:
        __use(0);
        ({ uint32_t _val = ({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; }); if (!tlb_write(tlb, cpu->edi, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
        if (!cpu->df)
            cpu->esi += 32 / 8;
        else
            cpu->esi -= 32 / 8;
        if (!cpu->df)
            cpu->edi += 32 / 8;
        else
            cpu->edi -= 32 / 8;
        break;
    case 0xa6:
        __use(0);
        cpu->op1 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
        cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        if (!cpu->df)
            cpu->esi += 8 / 8;
        else
            cpu->esi -= 8 / 8;
        if (!cpu->df)
            cpu->edi += 8 / 8;
        else
            cpu->edi -= 8 / 8;
        break;
    case 0xa7:
        __use(0);
        cpu->op1 = ({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
        cpu->op2 = ({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        if (!cpu->df)
            cpu->esi += 32 / 8;
        else
            cpu->esi -= 32 / 8;
        if (!cpu->df)
            cpu->edi += 32 / 8;
        else
            cpu->edi -= 32 / 8;
        break;

    case 0xa8:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->res = (int32_t)(int8_t)(((uint8_t)cpu->eax) & ((uint8_t)imm));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        break;
    case 0xa9:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        cpu->res = (int32_t)(int32_t)(((uint32_t)cpu->eax) & ((uint32_t)imm));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        break;

    case 0xaa:
        __use(0);
        ({ uint8_t _val = ((uint8_t) cpu->eax); if (!tlb_write(tlb, cpu->edi, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
        if (!cpu->df)
            cpu->edi += 8 / 8;
        else
            cpu->edi -= 8 / 8;
        break;
    case 0xab:
        __use(0);
        ({ uint32_t _val = ((uint32_t) cpu->eax); if (!tlb_write(tlb, cpu->edi, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
        if (!cpu->df)
            cpu->edi += 32 / 8;
        else
            cpu->edi -= 32 / 8;
        break;
    case 0xac:
        __use(0);
        *(uint8_t *)&cpu->eax = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
        if (!cpu->df)
            cpu->esi += 8 / 8;
        else
            cpu->esi -= 8 / 8;
        break;
    case 0xad:
        __use(0);
        *(uint32_t *)&cpu->eax = ({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
        if (!cpu->df)
            cpu->esi += 32 / 8;
        else
            cpu->esi -= 32 / 8;
        break;
    case 0xae:
        __use(0);
        cpu->op1 = ((uint8_t)cpu->eax);
        cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        if (!cpu->df)
            cpu->edi += 8 / 8;
        else
            cpu->edi -= 8 / 8;
        break;
    case 0xaf:
        __use(0);
        cpu->op1 = ((uint32_t)cpu->eax);
        cpu->op2 = ({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint32_t) (((uint32_t) cpu->eax)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int32_t) (((uint32_t) cpu->eax)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        if (!cpu->df)
            cpu->edi += 32 / 8;
        else
            cpu->edi -= 32 / 8;
        break;

    case 0xb0:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->eax = ((uint8_t)imm);
        break;
    case 0xb1:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->ecx = ((uint8_t)imm);
        break;
    case 0xb2:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->edx = ((uint8_t)imm);
        break;
    case 0xb3:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->ebx = ((uint8_t)imm);
        break;
    case 0xb4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->esp = ((uint8_t)imm);
        break;
    case 0xb5:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->ebp = ((uint8_t)imm);
        break;
    case 0xb6:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->esi = ((uint8_t)imm);
        break;
    case 0xb7:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->edi = ((uint8_t)imm);
        break;

    case 0xb8:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->eax = ((uint32_t)imm);
        break;
    case 0xb9:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->ecx = ((uint32_t)imm);
        break;
    case 0xba:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->edx = ((uint32_t)imm);
        break;
    case 0xbb:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->ebx = ((uint32_t)imm);
        break;
    case 0xbc:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->esp = ((uint32_t)imm);
        break;
    case 0xbd:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->ebp = ((uint32_t)imm);
        break;
    case 0xbe:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->esi = ((uint32_t)imm);
        break;
    case 0xbf:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        *(uint32_t *)&cpu->edi = ((uint32_t)imm);
        break;
# 1206 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0xc0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (8 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = ((int8_t) (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;
    case 0xc1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (((uint8_t)imm) % 32 != 0)
            {
                int cnt = ((uint8_t)imm) % 32;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - cnt);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - cnt); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (((uint8_t)imm) % 32 != 0)
            {
                int cnt = ((uint8_t)imm) % 32;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (32 - cnt);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (32 - cnt); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (((uint8_t)imm) % 32 != 0)
            {
                int cnt = ((uint8_t)imm) % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (32 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (((uint8_t)imm) % 32 != 0)
            {
                int cnt = ((uint8_t)imm) % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (((uint8_t)imm) % 32 != 0)
            {
                int cnt = ((uint8_t)imm) % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = ((int32_t)(modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint32_t _val = ((int32_t) (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;

    case 0xc2:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->eip = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        if (32 == 16)
            cpu->eip &= 0xffff;
        cpu->esp += ((uint16_t)imm);
        break;
    case 0xc3:
        __use(0);
        cpu->eip = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        if (32 == 16)
            cpu->eip &= 0xffff;
        cpu->esp += 0;
        break;

    case 0xc9:
        __use(0);
        *(uint32_t *)&cpu->esp = ((uint32_t)cpu->ebp);
        *(uint32_t *)&cpu->ebp = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 32 / 8;
        break;

    case 0xcd:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        return ((uint8_t)imm);
        break;

    case 0xc6:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((uint8_t)imm);
        }
        else
        {
            ({ uint8_t _val = ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;
    case 0xc7:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        if (modrm.type == modrm_reg)
        {
            (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = ((uint32_t)imm);
        }
        else
        {
            ({ uint32_t _val = ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;

    case 0xd0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (8 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = ((int8_t) (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;
    case 0xd1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (1 % 32 != 0)
            {
                int cnt = 1 % 32;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - cnt);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - cnt); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (1 % 32 != 0)
            {
                int cnt = 1 % 32;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (32 - cnt);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (32 - cnt); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (1 % 32 != 0)
            {
                int cnt = 1 % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (32 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (1 % 32 != 0)
            {
                int cnt = 1 % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (1 % 32 != 0)
            {
                int cnt = 1 % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = ((int32_t)(modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint32_t _val = ((int32_t) (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;
    case 0xd2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (8 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = ((int8_t) (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;
    case 0xd3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (((uint8_t)cpu->ecx) % 32 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 32;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - cnt);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - cnt); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (((uint8_t)cpu->ecx) % 32 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 32;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (32 - cnt);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (32 - cnt); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (((uint8_t)cpu->ecx) % 32 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (32 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (((uint8_t)cpu->ecx) % 32 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (32 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (((uint8_t)cpu->ecx) % 32 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 32;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = ((int32_t)(modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint32_t _val = ((int32_t) (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;

    case 0xd8:
    case 0xd9:
    case 0xda:
    case 0xdb:
    case 0xdc:
    case 0xdd:
    case 0xde:
    case 0xdf:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type != modrm_reg)
        {
            switch (insn << 4 | modrm.opcode)
            {
            case 0xd80:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd81:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd82:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd83:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->top++;
                break;
            case 0xd84:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd85:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xd86:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd87:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xd90:
                __use(0);
                ftmp = f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xd92:
                __use(0);
                ({ float _val = f80_to_double(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xd93:
                __use(0);
                ({ float _val = f80_to_double(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;

            case 0xd94:
                __use(0);

                break;

            case 0xd95:
                __use(0);
                cpu->fcw = ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; });
                break;

            case 0xd96:

                break;

            case 0xd97:
                __use(0);
                ({ uint16_t _val = cpu->fcw; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xda0:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xda1:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xda2:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                break;
            case 0xda3:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                cpu->top++;
                break;
            case 0xda4:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xda5:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xda6:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xda7:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xdb0:
                __use(0);
                ftmp = f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdb2:
                __use(0);
                ({ uint32_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xdb3:
                __use(0);
                ({ uint32_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;
            case 0xdb5:
                __use(0);
                ftmp = ({ float80 val; if (!tlb_read(tlb, addr, &val, 80/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; });
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdb7:
                __use(0);
                ({ float80 _val = cpu->fp[cpu->top + 0]; if (!tlb_write(tlb, addr, &_val, 80/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;
            case 0xdc0:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc1:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc2:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc3:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->top++;
                break;
            case 0xdc4:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc5:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xdc6:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc7:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xdd0:
                __use(0);
                ftmp = f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdd2:
                __use(0);
                ({ double _val = f80_to_double(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xdd3:
                __use(0);
                ({ double _val = f80_to_double(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;

            case 0xde0:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xde1:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xde2:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                break;
            case 0xde3:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                cpu->top++;
                break;
            case 0xde4:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xde5:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xde6:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xde7:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xdf0:
                __use(0);
                ftmp = f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdf2:
                __use(0);
                ({ uint16_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xdf3:
                __use(0);
                ({ uint16_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;
            case 0xdf5:
                __use(0);
                ftmp = f80_from_int((int64_t)({ uint64_t val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdf7:
                __use(0);
                ({ uint64_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            }
        }
        else
        {
            switch (insn << 4 | modrm.opcode)
            {
            case 0xd80:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd81:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd82:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd83:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                break;
            case 0xd84:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd85:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xd86:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd87:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xd90:
                __use(0);
                ftmp = cpu->fp[cpu->top + modrm.rm_opcode];
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xd91:
                __use(0);
                float80 ftmp = cpu->fp[cpu->top + 0];
                cpu->fp[cpu->top + 0] = cpu->fp[cpu->top + modrm.rm_opcode];
                cpu->fp[cpu->top + modrm.rm_opcode] = ftmp;
                break;
            case 0xdb5:
                __use(0);
                cpu->zf = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->cf = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->pf = 0;
                cpu->pf_res = 0;
                break;
            case 0xdb6:
                __use(0);
                cpu->zf = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->cf = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->pf = 0;
                cpu->pf_res = 0;
                break;
            case 0xdc0:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_add(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xdc1:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_mul(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xdc4:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_sub(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xdc5:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_sub(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xdc6:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_div(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xdc7:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_div(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xdd0:
                __use(0);
                break;
            case 0xdd3:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = cpu->fp[cpu->top + 0];
                cpu->top++;
                break;
            case 0xdd4:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xdd5:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                break;
            case 0xda5:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                cpu->top++;
                break;
            case 0xde0:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_add(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                cpu->top++;
                break;
            case 0xde1:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_mul(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                cpu->top++;
                break;
            case 0xde4:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_sub(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                break;
            case 0xde5:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_sub(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                cpu->top++;
                break;
            case 0xde6:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_div(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                break;
            case 0xde7:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_div(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                cpu->top++;
                break;
            case 0xdf0:
                __use(0);
                cpu->top++;
                break;
            case 0xdf5:
                __use(0);
                cpu->zf = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->cf = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->pf = 0;
                cpu->pf_res = 0;
                cpu->top++;
                break;
            case 0xdf6:
                __use(0);
                cpu->zf = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->cf = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->pf = 0;
                cpu->pf_res = 0;
                cpu->top++;
                break;
            default:
                switch (insn << 8 | modrm.opcode << 4 | modrm.rm_opcode)
                {
                case 0xd940:
                    __use(0);
                    cpu->fp[cpu->top + 0] = f80_neg(cpu->fp[cpu->top + 0]);
                    break;
                case 0xd941:
                    __use(0);
                    cpu->fp[cpu->top + 0] = f80_abs(cpu->fp[cpu->top + 0]);
                    break;
                case 0xd944:
                    __use(0);
                    cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], fpu_consts[fconst_zero]);
                    cpu->c1 = 0;
                    cpu->c2 = 0;
                    cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], fpu_consts[fconst_zero]);
                    break;
                case 0xd945:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;
                case 0xd950:
                    __use(0);
                    ftmp = fpu_consts[fconst_one];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd951:
                    __use(0);
                    ftmp = fpu_consts[fconst_log2t];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd952:
                    __use(0);
                    ftmp = fpu_consts[fconst_log2e];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd953:
                    __use(0);
                    ftmp = fpu_consts[fconst_pi];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd954:
                    __use(0);
                    ftmp = fpu_consts[fconst_log2];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd955:
                    __use(0);
                    ftmp = fpu_consts[fconst_ln2];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd956:
                    __use(0);
                    ftmp = fpu_consts[fconst_zero];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd960:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;
                case 0xd961:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;

                case 0xd970:
                    __use(0);
                    cpu->fp[cpu->top + 0] = f80_mod(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + 1]);
                    break;
                case 0xd972:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;
                case 0xd974:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;
                case 0xd975:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;

                case 0xde31:
                    __use(0);
                    cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                    cpu->c1 = 0;
                    cpu->c2 = 0;
                    cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                    cpu->top++;
                    cpu->top++;
                    break;
                case 0xdf40:
                    __use(0);
                    *(uint16_t *)&cpu->eax = cpu->fsw;
                    break;
                default:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                }
            }
        }
        break;

    case 0xe3:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (((uint32_t)cpu->ecx) == 0)
        {
            cpu->eip += ((uint32_t)imm);
            if (32 == 16)
                cpu->eip &= 0xffff;
        };
        break;

    case 0xe8:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        ({ uint32_t _val = cpu->eip; if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
        cpu->esp -= 32 / 8;
        cpu->eip += ((uint32_t)imm);
        if (32 == 16)
            cpu->eip &= 0xffff;
        ;
        break;

    case 0xe9:
        __use(0);
        imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)imm);
        cpu->eip += ((uint32_t)imm);
        if (32 == 16)
            cpu->eip &= 0xffff;
        ;
        break;
    case 0xeb:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->eip += ((uint32_t)imm);
        if (32 == 16)
            cpu->eip &= 0xffff;
        ;
        break;

    case 0xf0:
    lockrestart:
        insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, insn);
        switch (insn)
        {
        case 0x65:
            __use(0);
            addr += cpu->tls_ptr;
            goto lockrestart;

        case 0x66:

            __use(0);
            cpu->eip = saved_ip;
            return cpu_step16(cpu, tlb);
# 1405 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0x00 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x00 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x08 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x08 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x10 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == ((uint8_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == (uint8_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x10 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) == ((uint32_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) == (uint32_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x18 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == ((uint8_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == (uint8_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x18 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) == ((uint32_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) == (uint32_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x20 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x20 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x28 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x28 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x30 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x30 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
            }
            else
            {
                ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
# 1427 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0x80:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                cpu->op1 = ((uint8_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 1:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint8_t)imm);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 2:
                __use(0);
                cpu->op1 = ((uint8_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 3:
                __use(0);
                cpu->op1 = ((uint8_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 4:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t)imm);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 5:
                __use(0);
                cpu->op1 = ((uint8_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 6:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint8_t)imm);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;
        case 0x81:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 1:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint32_t)imm);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 2:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 3:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 4:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t)imm);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 5:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 6:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint32_t)imm);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;
        case 0x83:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 1:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint32_t)imm);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 2:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 3:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm) + cpu->cf), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == ((uint32_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm) + cpu->cf), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; }) || (cpu->cf && ((uint32_t)imm) == (uint32_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 4:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t)imm);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 5:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) imm)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 6:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint32_t)imm);
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint32_t) imm); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;

        case 0x0f:
            insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, insn);
            switch (insn)
            {
            case 0xab:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32));
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            case 0xb3:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32));
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            case 0xbb:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << ((*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) % 32));
                }
                else
                {
                    ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
# 1453 "/Users/bbarrows/repos/ish2/emu/interp.c"
            case 0xba:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
                cpu->eip += 8 / 8;
                __use(0, (long long)imm);
                imm = (int8_t)(uint8_t)imm;
                switch (modrm.opcode)
                {
                case 5:
                    __use(0);
                    cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + ((uint32_t) imm) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint32_t) imm) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint32_t)imm) % 32))) ? 1 : 0;
                    ;
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << (((uint32_t)imm) % 32));
                    }
                    else
                    {
                        ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << (((uint32_t) imm) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    break;
                case 6:
                    __use(0);
                    cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + ((uint32_t) imm) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint32_t) imm) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint32_t)imm) % 32))) ? 1 : 0;
                    ;
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << (((uint32_t)imm) % 32));
                    }
                    else
                    {
                        ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << (((uint32_t) imm) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    break;
                case 7:
                    __use(0);
                    cpu->cf = (((modrm.type != modrm_reg) ? ({ uint32_t val; if (!tlb_read(tlb, addr + ((uint32_t) imm) / 32 * (32/8), &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint32_t) imm) / 32 * (32/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint32_t)imm) % 32))) ? 1 : 0;
                    ;
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << (((uint32_t)imm) % 32));
                    }
                    else
                    {
                        ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << (((uint32_t) imm) % 32)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    break;
                default:
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                };
                break;

            case 0xb0:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                if (modrm.type == modrm_reg)
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                cpu->op1 = ((uint8_t)cpu->eax);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                {
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                    }
                    else
                    {
                        ({ uint8_t _val = (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                }
                else
                    *(uint8_t *)&cpu->eax = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                break;
            case 0xb1:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                if (modrm.type == modrm_reg)
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                cpu->op1 = ((uint32_t)cpu->eax);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (((uint32_t) cpu->eax)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (((uint32_t) cpu->eax)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                {
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
                    }
                    else
                    {
                        ({ uint32_t _val = (*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id)); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                }
                else
                    *(uint32_t *)&cpu->eax = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                break;

            case 0xc0:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                if (modrm.type == modrm_reg)
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                do
                {
                    dword_t tmp = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                    (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = tmp;
                    }
                    else
                    {
                        ({ uint8_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                } while (0);
                cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 0xc1:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                if (modrm.type == modrm_reg)
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                do
                {
                    dword_t tmp = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
                    (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = tmp;
                    }
                    else
                    {
                        ({ uint32_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                } while (0);
                cpu->op1 = (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id));
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) ((*(uint32_t *) (((char *) cpu) + (modrm_regptr).reg32_id))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;

            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            }
            break;
# 1484 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0xfe:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                do
                {
                    int tmp = cpu->cf;
                    cpu->op1 = 1;
                    cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    cpu->af_ops = 1;
                    cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (1), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                    cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (1), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                    }
                    else
                    {
                        ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                    cpu->cf = tmp;
                } while (0);
                break;
            case 1:
                __use(0);
                do
                {
                    int tmp = cpu->cf;
                    cpu->op1 = 1;
                    cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    cpu->af_ops = 1;
                    cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (1), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                    cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (1), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                    }
                    else
                    {
                        ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                    cpu->cf = tmp;
                } while (0);
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;
        case 0xff:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                do
                {
                    int tmp = cpu->cf;
                    cpu->op1 = 1;
                    cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    cpu->af_ops = 1;
                    cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                    cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                    }
                    else
                    {
                        ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                    cpu->cf = tmp;
                } while (0);
                break;
            case 1:
                __use(0);
                do
                {
                    int tmp = cpu->cf;
                    cpu->op1 = 1;
                    cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    cpu->af_ops = 1;
                    cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                    cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                    }
                    else
                    {
                        ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                    cpu->cf = tmp;
                } while (0);
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;

        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        }
        break;

    case 0xf2:
        insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, insn);
        switch (insn)
        {
        case 0x0f:
            insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, insn);
            switch (insn)
            {

            case 0x11:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                break;

            case 0x18 ... 0x1f:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            }
            break;

        case 0xa6:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->esi += 8 / 8;
                else
                    cpu->esi -= 8 / 8;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xa7:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->op2 = ({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->esi += 32 / 8;
                else
                    cpu->esi -= 32 / 8;
                if (!cpu->df)
                    cpu->edi += 32 / 8;
                else
                    cpu->edi -= 32 / 8;
                cpu->ecx--;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xae:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ((uint8_t)cpu->eax);
                cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xaf:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ((uint32_t)cpu->eax);
                cpu->op2 = ({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint32_t) (((uint32_t) cpu->eax)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int32_t) (((uint32_t) cpu->eax)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->edi += 32 / 8;
                else
                    cpu->edi -= 32 / 8;
                cpu->ecx--;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        }
        break;

    case 0xf3:
        insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, insn);
        switch (insn)
        {
        case 0x0f:

            insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, insn);
            switch (insn)
            {

            case 0x11:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                break;

            case 0x18 ... 0x1f:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                break;

            case 0xbc:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->zf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0;
                cpu->zf_res = 0;
                if (!cpu->zf)
                    (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = __builtin_ctz((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xbd:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->zf = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0;
                cpu->zf_res = 0;
                if (!cpu->zf)
                    (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = 32 - __builtin_clz((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;

            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            }
            break;

        case 0x90:
            __use(0);
            break;

        case 0xa4:
            __use(0);
            while (cpu->ecx != 0)
            {
                ({ uint8_t _val = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; }); if (!tlb_write(tlb, cpu->edi, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
                if (!cpu->df)
                    cpu->esi += 8 / 8;
                else
                    cpu->esi -= 8 / 8;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
            };
            break;
        case 0xa5:
            __use(0);
            while (cpu->ecx != 0)
            {
                ({ uint32_t _val = ({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; }); if (!tlb_write(tlb, cpu->edi, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
                if (!cpu->df)
                    cpu->esi += 32 / 8;
                else
                    cpu->esi -= 32 / 8;
                if (!cpu->df)
                    cpu->edi += 32 / 8;
                else
                    cpu->edi -= 32 / 8;
                cpu->ecx--;
            };
            break;
        case 0xa6:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->esi += 8 / 8;
                else
                    cpu->esi -= 8 / 8;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
                if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xa7:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->op2 = ({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->esi += 32 / 8;
                else
                    cpu->esi -= 32 / 8;
                if (!cpu->df)
                    cpu->edi += 32 / 8;
                else
                    cpu->edi -= 32 / 8;
                cpu->ecx--;
                if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xaa:
            __use(0);
            while (cpu->ecx != 0)
            {
                ({ uint8_t _val = ((uint8_t) cpu->eax); if (!tlb_write(tlb, cpu->edi, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
            };
            break;
        case 0xab:
            __use(0);
            while (cpu->ecx != 0)
            {
                ({ uint32_t _val = ((uint32_t) cpu->eax); if (!tlb_write(tlb, cpu->edi, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
                if (!cpu->df)
                    cpu->edi += 32 / 8;
                else
                    cpu->edi -= 32 / 8;
                cpu->ecx--;
            };
            break;
        case 0xac:
            __use(0);
            while (cpu->ecx != 0)
            {
                *(uint8_t *)&cpu->eax = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                if (!cpu->df)
                    cpu->esi += 8 / 8;
                else
                    cpu->esi -= 8 / 8;
                cpu->ecx--;
            };
            break;
        case 0xad:
            __use(0);
            while (cpu->ecx != 0)
            {
                *(uint32_t *)&cpu->eax = ({ uint32_t val; if (!tlb_read(tlb, cpu->esi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                if (!cpu->df)
                    cpu->esi += 32 / 8;
                else
                    cpu->esi -= 32 / 8;
                cpu->ecx--;
            };
            break;
        case 0xae:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ((uint8_t)cpu->eax);
                cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
                if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xaf:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ((uint32_t)cpu->eax);
                cpu->op2 = ({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint32_t) (((uint32_t) cpu->eax)), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (({ uint32_t val; if (!tlb_read(tlb, cpu->edi, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int32_t) (((uint32_t) cpu->eax)), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->edi += 32 / 8;
                else
                    cpu->edi -= 32 / 8;
                cpu->ecx--;
                if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;

        case 0xc3:
            __use(0);
            cpu->eip = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
            cpu->esp += 32 / 8;
            if (32 == 16)
                cpu->eip &= 0xffff;
            cpu->esp += 0;
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        }
        break;
# 1595 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0xf6:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
        case 1:
            __use(0);
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t)imm));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            break;
        case 2:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ~(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            }
            else
            {
                ({ uint8_t _val = ~(modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 3:
            __use(0);
            cpu->op1 = 0;
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (0), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (0), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
            break;
        case 4:
            __use(0);
            do
            {
                uint64_t tmp = ((uint8_t)cpu->eax) * (uint64_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint8_t *)&cpu->eax = tmp;
                *(uint8_t *)&cpu->edx = tmp >> 8;
                ;
                cpu->cf = cpu->of = (tmp != (uint32_t)tmp);
                cpu->af = cpu->af_ops = 0;
                cpu->zf = cpu->sf = cpu->pf = cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
            } while (0);
            break;
        case 5:
            __use(0);
            do
            {
                int64_t tmp = (int64_t)(int8_t)((uint8_t)cpu->eax) * (int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint8_t *)&cpu->eax = tmp;
                *(uint8_t *)&cpu->edx = tmp >> 8;
                cpu->cf = cpu->of = (tmp != (int32_t)tmp);
                cpu->zf = cpu->sf = cpu->pf = cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
            } while (0);
            break;
        case 6:
            __use(0);
            do
            {
                if ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0)
                    return 0;
                uint16_t dividend = ((uint8_t)cpu->eax) | ((uint16_t)((uint8_t)cpu->edx) << 8);
                *(uint8_t *)&cpu->edx = dividend % (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint8_t *)&cpu->eax = dividend / (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            } while (0);
            break;
        case 7:
            __use(0);
            do
            {
                if ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0)
                    return 0;
                int16_t dividend = ((uint8_t)cpu->eax) | ((int16_t)((uint8_t)cpu->edx) << 8);
                *(uint8_t *)&cpu->edx = dividend % (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint8_t *)&cpu->eax = dividend / (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            } while (0);
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;
    case 0xf7:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
        case 1:
            __use(0);
            imm = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 32 / 8;
            __use(0, (long long)imm);
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint32_t)imm));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            break;
        case 2:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = ~(modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            }
            else
            {
                ({ uint32_t _val = ~(modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 3:
            __use(0);
            cpu->op1 = 0;
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) (0), (int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) (0), (uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
            }
            else
            {
                ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
            break;
        case 4:
            __use(0);
            do
            {
                uint64_t tmp = ((uint32_t)cpu->eax) * (uint64_t)(modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint32_t *)&cpu->eax = tmp;
                *(uint32_t *)&cpu->edx = tmp >> 32;
                ;
                cpu->cf = cpu->of = (tmp != (uint32_t)tmp);
                cpu->af = cpu->af_ops = 0;
                cpu->zf = cpu->sf = cpu->pf = cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
            } while (0);
            break;
        case 5:
            __use(0);
            do
            {
                int64_t tmp = (int64_t)(int32_t)((uint32_t)cpu->eax) * (int32_t)(modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint32_t *)&cpu->eax = tmp;
                *(uint32_t *)&cpu->edx = tmp >> 32;
                cpu->cf = cpu->of = (tmp != (int32_t)tmp);
                cpu->zf = cpu->sf = cpu->pf = cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
            } while (0);
            break;
        case 6:
            __use(0);
            do
            {
                if ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0)
                    return 0;
                uint64_t dividend = ((uint32_t)cpu->eax) | ((uint64_t)((uint32_t)cpu->edx) << 32);
                *(uint32_t *)&cpu->edx = dividend % (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint32_t *)&cpu->eax = dividend / (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            } while (0);
            break;
        case 7:
            __use(0);
            do
            {
                if ((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0)
                    return 0;
                int64_t dividend = ((uint32_t)cpu->eax) | ((int64_t)((uint32_t)cpu->edx) << 32);
                *(uint32_t *)&cpu->edx = dividend % (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint32_t *)&cpu->eax = dividend / (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            } while (0);
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;

    case 0xfc:
        __use(0);
        cpu->df = 0;
        break;
    case 0xfd:
        __use(0);
        cpu->df = 1;
        break;
# 1622 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0xfe:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            do
            {
                int tmp = cpu->cf;
                cpu->op1 = 1;
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (1), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (1), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->cf = tmp;
            } while (0);
            break;
        case 1:
            __use(0);
            do
            {
                int tmp = cpu->cf;
                cpu->op1 = 1;
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (1), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (1), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->cf = tmp;
            } while (0);
            break;
        case 2:
            __use(0);
            ({ uint32_t _val = cpu->eip; if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
            cpu->esp -= 32 / 8;
            cpu->eip = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (32 == 16)
                cpu->eip &= 0xffff;
            ;
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        case 4:
            __use(0);
            cpu->eip = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (32 == 16)
                cpu->eip &= 0xffff;
            ;
            break;
        case 5:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        case 6:
            __use(0);
            ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
            cpu->esp -= 32 / 8;
            break;
        case 7:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;
    case 0xff:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            do
            {
                int tmp = cpu->cf;
                cpu->op1 = 1;
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->cf = tmp;
            } while (0);
            break;
        case 1:
            __use(0);
            do
            {
                int tmp = cpu->cf;
                cpu->op1 = 1;
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int32_t) (1), (int32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint32_t) ((modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint32_t) (1), (uint32_t *) &cpu->res); cpu->res = (int32_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) = cpu->res;
                }
                else
                {
                    ({ uint32_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->cf = tmp;
            } while (0);
            break;
        case 2:
            __use(0);
            ({ uint32_t _val = cpu->eip; if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
            cpu->esp -= 32 / 8;
            cpu->eip = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (32 == 16)
                cpu->eip &= 0xffff;
            ;
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        case 4:
            __use(0);
            cpu->eip = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (32 == 16)
                cpu->eip &= 0xffff;
            ;
            break;
        case 5:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        case 6:
            __use(0);
            ({ uint32_t _val = (modrm.type == modrm_reg ? (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
            cpu->esp -= 32 / 8;
            break;
        case 7:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;

    default:
        __use(0);
        {
            cpu->eip = saved_ip;
            return 6;
        };
    }
    __use(0);
    return -1;
}
# 1657 "/Users/bbarrows/repos/ish2/emu/interp.c"
extern int current_pid(void);

__attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) int cpu_step16(struct cpu_state *cpu, struct tlb *tlb)
{
    dword_t addr_offset = 0;
    dword_t saved_ip = cpu->eip;
    struct regptr modrm_regptr, modrm_base;
    dword_t addr = 0;
    union xmm_reg xmm_src;
    union xmm_reg xmm_dst;
    float80 ftmp;
    ;
# 1672 "/Users/bbarrows/repos/ish2/emu/interp.c"
    byte_t insn;
    uint64_t imm = 0;
    struct modrm modrm;
# 1683 "/Users/bbarrows/repos/ish2/emu/interp.c"
restart:

    insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
    cpu->eip += 8 / 8;
    __use(0, insn);

    switch (insn)
    {
# 1712 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0x00 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
        }
        else
        {
            ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
        }
        else
        {
            ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        *(uint8_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x00 + 0x5:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint16_t)imm);
        cpu->op2 = ((uint16_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->eax)), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->eax)), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        *(uint16_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        }
        else
        {
            ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        }
        else
        {
            ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) | (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->eax = ((uint8_t)cpu->eax) | ((uint8_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)(((uint8_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x08 + 0x5:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->eax = ((uint16_t)cpu->eax) | ((uint16_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)(((uint16_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;

    case 0x0f:

        insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, insn);
        switch (insn)
        {
        case 0x18 ... 0x1f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            break;

        case 0x28:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 0x29:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;

        case 0x31:

            __use(0);
            imm = ({ uint32_t low, high; __asm__ volatile("rdtsc" : "=a" (high), "=d" (low)); ((uint64_t) high) << 32 | low; });
            cpu->eax = imm & 0xffffffff;
            cpu->edx = imm >> 32;
            break;

        case 0x40:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->of))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x41:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->of))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x42:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->cf))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x43:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->cf))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x44:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x45:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x46:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x47:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x48:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x49:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4a:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4b:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4c:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4d:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4e:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0x4f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (!(((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
# 1777 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0x6f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
# 1788 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0x77:
            __use(0);
            break;

        case 0x7e:
            __use(0);

            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;

        case 0x7f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;

        case 0x80:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if ((cpu->of))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x81:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (!(cpu->of))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x82:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if ((cpu->cf))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x83:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (!(cpu->cf))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x84:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x85:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x86:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x87:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (!((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x88:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x89:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (!(cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8a:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8b:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (!(cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8c:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8d:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (!((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8e:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;
        case 0x8f:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            if (!(((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
            {
                cpu->eip += ((uint16_t)imm);
                if (16 == 16)
                    cpu->eip &= 0xffff;
            };
            break;

        case 0x90:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->of) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->of) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x91:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->of) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->of) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x92:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->cf) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->cf) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x93:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->cf) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->cf) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x94:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->zf_res ? cpu->res == 0 : cpu->zf) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->zf_res ? cpu->res == 0 : cpu->zf) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x95:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->zf_res ? cpu->res == 0 : cpu->zf) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->zf_res ? cpu->res == 0 : cpu->zf) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x96:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x97:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x98:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x99:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9a:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9b:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9c:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = (((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ^ (cpu->of)) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9d:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = (((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ^ (cpu->of)) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9e:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 1 : 0);
            }
            else
            {
                ({ uint8_t _val = ((((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 1 : 0); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0x9f:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 0 : 1);
            }
            else
            {
                ({ uint8_t _val = ((((cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)) ? 0 : 1); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;

        case 0xa2:
            __use(0);
            do_cpuid(&cpu->eax, &cpu->ebx, &cpu->ecx, &cpu->edx);
            break;

        case 0xa3:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16))) ? 1 : 0;
            ;
            break;

        case 0xa4:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            if (((uint8_t)imm) % 16 != 0)
            {
                int cnt = ((uint8_t)imm) % 16;
                cpu->res = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) >> (16 - cnt);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            };
            break;
        case 0xa5:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (((uint8_t)cpu->ecx) % 16 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 16;
                cpu->res = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) >> (16 - cnt);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            };
            break;

        case 0xab:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16))) ? 1 : 0;
            ;
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16));
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;

        case 0xac:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            if (((uint8_t)imm) % 16 != 0)
            {
                int cnt = ((uint8_t)imm) % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->res = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) << (16 - cnt);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            };
            break;
        case 0xad:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (((uint8_t)cpu->ecx) % 16 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->res = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) << (16 - cnt);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            };
            break;

        case 0xaf:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = cpu->of = ({ int ov = __builtin_mul_overflow((int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;

        case 0xb0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = ((uint8_t)cpu->eax);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
            {
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                }
                else
                {
                    ({ uint8_t _val = (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
            }
            else
                *(uint8_t *)&cpu->eax = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0xb1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = ((uint16_t)cpu->eax);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) cpu->eax)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) cpu->eax)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
            {
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
                }
                else
                {
                    ({ uint16_t _val = (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
            }
            else
                *(uint16_t *)&cpu->eax = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;

        case 0xb3:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16))) ? 1 : 0;
            ;
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16));
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;

        case 0xb6:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0xb7:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
# 1907 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0xba:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            switch (modrm.opcode)
            {
            case 4:
                __use(0);
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + ((uint16_t) imm) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint16_t) imm) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint16_t)imm) % 16))) ? 1 : 0;
                ;
                break;
            case 5:
                __use(0);
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + ((uint16_t) imm) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint16_t) imm) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint16_t)imm) % 16))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << (((uint16_t)imm) % 16));
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << (((uint16_t) imm) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            case 6:
                __use(0);
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + ((uint16_t) imm) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint16_t) imm) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint16_t)imm) % 16))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << (((uint16_t)imm) % 16));
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << (((uint16_t) imm) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            case 7:
                __use(0);
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + ((uint16_t) imm) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint16_t) imm) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint16_t)imm) % 16))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << (((uint16_t)imm) % 16));
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << (((uint16_t) imm) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            default:
            {
                cpu->eip = saved_ip;
                return 6;
            };
            };
            break;

        case 0xbb:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16))) ? 1 : 0;
            ;
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16));
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 0xbc:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->zf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0;
            cpu->zf_res = 0;
            if (!cpu->zf)
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = __builtin_ctz((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            break;
        case 0xbd:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            cpu->zf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0;
            cpu->zf_res = 0;
            if (!cpu->zf)
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = 16 - __builtin_clz((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            break;

        case 0xbe:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (uint16_t)(int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;
        case 0xbf:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (uint16_t)(int16_t)(modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            break;

        case 0xc0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            do
            {
                dword_t tmp = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = tmp;
                }
                else
                {
                    ({ uint8_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
            } while (0);
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0xc1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            do
            {
                dword_t tmp = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
                (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = tmp;
                }
                else
                {
                    ({ uint16_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
            } while (0);
            cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
# 1960 "/Users/bbarrows/repos/ish2/emu/interp.c"
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        }
        break;

    case 0x10 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == (uint8_t)-1);
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
        }
        else
        {
            ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) == ((uint16_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) == (uint16_t)-1);
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
        }
        else
        {
            ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == (uint8_t)-1);
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == ((uint16_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == (uint16_t)-1);
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
        *(uint8_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x10 + 0x5:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint16_t)imm);
        cpu->op2 = ((uint16_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->eax)), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->eax)), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
        *(uint16_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == (uint8_t)-1);
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
        }
        else
        {
            ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) == ((uint16_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) == (uint16_t)-1);
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
        }
        else
        {
            ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == (uint8_t)-1);
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == ((uint16_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == (uint16_t)-1);
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
        *(uint8_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x18 + 0x5:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint16_t)imm);
        cpu->op2 = ((uint16_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->eax)), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->eax)), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
        *(uint16_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        }
        else
        {
            ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        }
        else
        {
            ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) & (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) & (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->eax = ((uint8_t)cpu->eax) & ((uint8_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)(((uint8_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x20 + 0x5:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->eax = ((uint16_t)cpu->eax) & ((uint16_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)(((uint16_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
        }
        else
        {
            ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
        }
        else
        {
            ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        *(uint8_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x28 + 0x5:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint16_t)imm);
        cpu->op2 = ((uint16_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->eax)), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->eax)), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        *(uint16_t *)&cpu->eax = cpu->res;
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;

    case 0x2e:
        __use(0);
        goto restart;

    case 0x30 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        }
        else
        {
            ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        }
        else
        {
            ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) ^ (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)((*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) ^ (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->eax = ((uint8_t)cpu->eax) ^ ((uint8_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int8_t)(((uint8_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x30 + 0x5:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->eax = ((uint16_t)cpu->eax) ^ ((uint16_t)imm);
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        cpu->res = (int32_t)(int16_t)(((uint16_t)cpu->eax));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->op1 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        cpu->op2 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->op1 = ((uint8_t)imm);
        cpu->op2 = ((uint8_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (((uint8_t) cpu->eax)), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (((uint8_t) cpu->eax)), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;
    case 0x38 + 0x5:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->op1 = ((uint16_t)imm);
        cpu->op2 = ((uint16_t)cpu->eax);
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->eax)), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->eax)), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        break;

    case 0x3e:
        __use(0);
        goto restart;

    case 0x40:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->eax);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->eax)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->eax)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->eax = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x41:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->ecx);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->ecx)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->ecx)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->ecx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x42:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->edx);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->edx)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->edx)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->edx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x43:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->ebx);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->ebx)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->ebx)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->ebx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x44:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->esp);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->esp)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->esp)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->esp = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x45:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->ebp);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->ebp)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->ebp)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->ebp = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x46:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->esi);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->esi)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->esi)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->esi = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x47:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->edi);
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) (((uint16_t) cpu->edi)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) (((uint16_t) cpu->edi)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->edi = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x48:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->eax);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->eax)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->eax)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->eax = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x49:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->ecx);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->ecx)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->ecx)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->ecx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4a:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->edx);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->edx)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->edx)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->edx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4b:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->ebx);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->ebx)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->ebx)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->ebx = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4c:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->esp);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->esp)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->esp)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->esp = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4d:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->ebp);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->ebp)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->ebp)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->ebp = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4e:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->esi);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->esi)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->esi)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->esi = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;
    case 0x4f:
        __use(0);
        do
        {
            int tmp = cpu->cf;
            cpu->op1 = 1;
            cpu->op2 = ((uint16_t)cpu->edi);
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (((uint16_t) cpu->edi)), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (((uint16_t) cpu->edi)), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            *(uint16_t *)&cpu->edi = cpu->res;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = tmp;
        } while (0);
        break;

    case 0x50:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->eax); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x51:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->ecx); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x52:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->edx); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x53:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->ebx); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x54:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->esp); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x55:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->ebp); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x56:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->esi); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x57:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->edi); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;

    case 0x58:
        __use(0);
        *(uint16_t *)&cpu->eax = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;
    case 0x59:
        __use(0);
        *(uint16_t *)&cpu->ecx = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;
    case 0x5a:
        __use(0);
        *(uint16_t *)&cpu->edx = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;
    case 0x5b:
        __use(0);
        *(uint16_t *)&cpu->ebx = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;
    case 0x5c:
        __use(0);
        *(uint16_t *)&cpu->esp = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;
    case 0x5d:
        __use(0);
        *(uint16_t *)&cpu->ebp = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;
    case 0x5e:
        __use(0);
        *(uint16_t *)&cpu->esi = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;
    case 0x5f:
        __use(0);
        *(uint16_t *)&cpu->edi = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;

    case 0x65:
        __use(0);
        addr += cpu->tls_ptr;
        goto restart;

    case 0x60:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->eax); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        ({ uint16_t _val = ((uint16_t) cpu->ecx); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        ({ uint16_t _val = ((uint16_t) cpu->edx); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        ({ uint16_t _val = ((uint16_t) cpu->ebx); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        ({ uint16_t _val = ((uint16_t) cpu->esp); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        ({ uint16_t _val = ((uint16_t) cpu->ebp); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        ({ uint16_t _val = ((uint16_t) cpu->esi); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        ({ uint16_t _val = ((uint16_t) cpu->edi); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x61:
        __use(0);
        *(uint16_t *)&cpu->edi = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        *(uint16_t *)&cpu->esi = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;

        *(uint16_t *)&cpu->ebp = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        *(uint16_t *)&cpu->ebx = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        *(uint16_t *)&cpu->ebx = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        *(uint16_t *)&cpu->edx = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        *(uint16_t *)&cpu->ecx = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        *(uint16_t *)&cpu->eax = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;

    case 0x66:

        __use(0);
        return cpu_step32(cpu, tlb);

    case 0x67:
        __use(0);
        goto restart;

    case 0x68:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        ({ uint16_t _val = ((uint16_t) imm); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x69:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->cf = cpu->of = ({ int ov = __builtin_mul_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = cpu->res;
        cpu->pf_res = 1;
        cpu->zf = cpu->sf = cpu->zf_res = cpu->sf_res = 0;
        break;
    case 0x6a:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        ({ uint16_t _val = ((uint16_t) imm); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x6b:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->cf = cpu->of = ({ int ov = __builtin_mul_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = cpu->res;
        cpu->pf_res = 1;
        cpu->zf = cpu->sf = cpu->zf_res = cpu->sf_res = 0;
        break;

    case 0x70:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->of))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x71:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->of))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x72:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->cf))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x73:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->cf))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x74:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x75:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x76:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x77:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!((cpu->cf) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x78:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x79:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7a:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7b:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7c:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7d:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7e:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if ((((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
    case 0x7f:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (!(((cpu->sf_res ? (int32_t)cpu->res < 0 : cpu->sf) ^ (cpu->of)) | (cpu->zf_res ? cpu->res == 0 : cpu->zf)))
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;
# 2103 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0x80:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 1:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint8_t)imm);
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 2:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 3:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 4:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t)imm);
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 5:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 6:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint8_t)imm);
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 7:
            __use(0);
            cpu->op1 = ((uint8_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;
    case 0x81:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 1:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint16_t)imm);
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 2:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 3:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 4:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t)imm);
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 5:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 6:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint16_t)imm);
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 7:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;
    case 0x83:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 1:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint16_t)imm);
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 2:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 3:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 4:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t)imm);
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 5:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 6:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint16_t)imm);
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 7:
            __use(0);
            cpu->op1 = ((uint16_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;

    case 0x84:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        break;
    case 0x85:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        break;

    case 0x86:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        do
        {
            dword_t tmp = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = tmp;
            }
            else
            {
                ({ uint8_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
        } while (0);
        break;
    case 0x87:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        do
        {
            dword_t tmp = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = tmp;
            }
            else
            {
                ({ uint16_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
        } while (0);
        break;

    case 0x88:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
        }
        else
        {
            ({ uint8_t _val = (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;
    case 0x89:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
        }
        else
        {
            ({ uint16_t _val = (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;
    case 0x8a:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        break;
    case 0x8b:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        break;

    case 0x8d:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            cpu->eip = saved_ip;
            return 6;
        };
        (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = addr;
        break;

    case 0x8c:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.reg != reg_ebp)
        {
            cpu->eip = saved_ip;
            return 6;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->gs;
        }
        else
        {
            ({ uint16_t _val = cpu->gs; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;
    case 0x8e:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.reg != reg_ebp)
        {
            cpu->eip = saved_ip;
            return 6;
        };
        cpu->gs = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
        break;

    case 0x8f:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        }
        else
        {
            ({ uint16_t _val = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; }); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        cpu->esp += 16 / 8;
        break;

    case 0x90:
        __use(0);
        break;
    case 0x91:
        __use(0);
        do
        {
            dword_t tmp = ((uint16_t)cpu->ecx);
            *(uint16_t *)&cpu->ecx = ((uint16_t)cpu->eax);
            *(uint16_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x92:
        __use(0);
        do
        {
            dword_t tmp = ((uint16_t)cpu->edx);
            *(uint16_t *)&cpu->edx = ((uint16_t)cpu->eax);
            *(uint16_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x93:
        __use(0);
        do
        {
            dword_t tmp = ((uint16_t)cpu->ebx);
            *(uint16_t *)&cpu->ebx = ((uint16_t)cpu->eax);
            *(uint16_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x94:
        __use(0);
        do
        {
            dword_t tmp = ((uint16_t)cpu->esp);
            *(uint16_t *)&cpu->esp = ((uint16_t)cpu->eax);
            *(uint16_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x95:
        __use(0);
        do
        {
            dword_t tmp = ((uint16_t)cpu->ebp);
            *(uint16_t *)&cpu->ebp = ((uint16_t)cpu->eax);
            *(uint16_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x96:
        __use(0);
        do
        {
            dword_t tmp = ((uint16_t)cpu->esi);
            *(uint16_t *)&cpu->esi = ((uint16_t)cpu->eax);
            *(uint16_t *)&cpu->eax = tmp;
        } while (0);
        break;
    case 0x97:
        __use(0);
        do
        {
            dword_t tmp = ((uint16_t)cpu->edi);
            *(uint16_t *)&cpu->edi = ((uint16_t)cpu->eax);
            *(uint16_t *)&cpu->eax = tmp;
        } while (0);
        break;

    case 0x98:
        __use(0);
        (*((uint8_t *)(((char *)(cpu)) + __builtin_offsetof(struct cpu_state, eax)))) = (int16_t)(*((uint16_t *)(((char *)(cpu)) + __builtin_offsetof(struct cpu_state, ax))));
        break;
    case 0x99:
        __use(0);
        *(uint16_t *)&cpu->edx = ((uint16_t)cpu->eax) & (1 << (16 - 1)) ? (uint16_t)-1 : 0;
        break;

    case 0x9b:
        __use(0);
        break;

    case 0x9c:
        __use(0);
        collapse_flags(cpu);
        ({ uint16_t _val = cpu->eflags; if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        break;
    case 0x9d:
        __use(0);
        cpu->eflags = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        expand_flags(cpu);
        break;
    case 0x9e:
        __use(0);
        cpu->eflags &= 0xffffff00 | ~0b11010101;
        cpu->eflags |= cpu->ah & 0b11010101;
        expand_flags(cpu);
        break;

    case 0xa0:
        __use(0);
        addr_offset = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)addr_offset);
        addr += addr_offset;
        *(uint8_t *)&cpu->eax = ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; });
        break;
    case 0xa1:
        __use(0);
        addr_offset = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)addr_offset);
        addr += addr_offset;
        *(uint16_t *)&cpu->eax = ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; });
        break;
    case 0xa2:
        __use(0);
        addr_offset = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)addr_offset);
        addr += addr_offset;
        ({ uint8_t _val = ((uint8_t) cpu->eax); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        break;
    case 0xa3:
        __use(0);
        addr_offset = ({ uint32_t val; if (!tlb_read(tlb, cpu->eip, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 32 / 8;
        __use(0, (long long)addr_offset);
        addr += addr_offset;
        ({ uint16_t _val = ((uint16_t) cpu->eax); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        break;

    case 0xa4:
        __use(0);
        ({ uint8_t _val = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; }); if (!tlb_write(tlb, cpu->edi, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
        if (!cpu->df)
            cpu->esi += 8 / 8;
        else
            cpu->esi -= 8 / 8;
        if (!cpu->df)
            cpu->edi += 8 / 8;
        else
            cpu->edi -= 8 / 8;
        break;
    case 0xa5:
        __use(0);
        ({ uint16_t _val = ({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; }); if (!tlb_write(tlb, cpu->edi, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
        if (!cpu->df)
            cpu->esi += 16 / 8;
        else
            cpu->esi -= 16 / 8;
        if (!cpu->df)
            cpu->edi += 16 / 8;
        else
            cpu->edi -= 16 / 8;
        break;
    case 0xa6:
        __use(0);
        cpu->op1 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
        cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        if (!cpu->df)
            cpu->esi += 8 / 8;
        else
            cpu->esi -= 8 / 8;
        if (!cpu->df)
            cpu->edi += 8 / 8;
        else
            cpu->edi -= 8 / 8;
        break;
    case 0xa7:
        __use(0);
        cpu->op1 = ({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
        cpu->op2 = ({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        if (!cpu->df)
            cpu->esi += 16 / 8;
        else
            cpu->esi -= 16 / 8;
        if (!cpu->df)
            cpu->edi += 16 / 8;
        else
            cpu->edi -= 16 / 8;
        break;

    case 0xa8:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->res = (int32_t)(int8_t)(((uint8_t)cpu->eax) & ((uint8_t)imm));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        break;
    case 0xa9:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->res = (int32_t)(int16_t)(((uint16_t)cpu->eax) & ((uint16_t)imm));
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
        break;

    case 0xaa:
        __use(0);
        ({ uint8_t _val = ((uint8_t) cpu->eax); if (!tlb_write(tlb, cpu->edi, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
        if (!cpu->df)
            cpu->edi += 8 / 8;
        else
            cpu->edi -= 8 / 8;
        break;
    case 0xab:
        __use(0);
        ({ uint16_t _val = ((uint16_t) cpu->eax); if (!tlb_write(tlb, cpu->edi, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
        if (!cpu->df)
            cpu->edi += 16 / 8;
        else
            cpu->edi -= 16 / 8;
        break;
    case 0xac:
        __use(0);
        *(uint8_t *)&cpu->eax = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
        if (!cpu->df)
            cpu->esi += 8 / 8;
        else
            cpu->esi -= 8 / 8;
        break;
    case 0xad:
        __use(0);
        *(uint16_t *)&cpu->eax = ({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
        if (!cpu->df)
            cpu->esi += 16 / 8;
        else
            cpu->esi -= 16 / 8;
        break;
    case 0xae:
        __use(0);
        cpu->op1 = ((uint8_t)cpu->eax);
        cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        if (!cpu->df)
            cpu->edi += 8 / 8;
        else
            cpu->edi -= 8 / 8;
        break;
    case 0xaf:
        __use(0);
        cpu->op1 = ((uint16_t)cpu->eax);
        cpu->op2 = ({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
        cpu->af_ops = 1;
        cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint16_t) (((uint16_t) cpu->eax)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int16_t) (((uint16_t) cpu->eax)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
        cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
        if (!cpu->df)
            cpu->edi += 16 / 8;
        else
            cpu->edi -= 16 / 8;
        break;

    case 0xb0:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->eax = ((uint8_t)imm);
        break;
    case 0xb1:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->ecx = ((uint8_t)imm);
        break;
    case 0xb2:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->edx = ((uint8_t)imm);
        break;
    case 0xb3:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->ebx = ((uint8_t)imm);
        break;
    case 0xb4:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->esp = ((uint8_t)imm);
        break;
    case 0xb5:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->ebp = ((uint8_t)imm);
        break;
    case 0xb6:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->esi = ((uint8_t)imm);
        break;
    case 0xb7:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        *(uint8_t *)&cpu->edi = ((uint8_t)imm);
        break;

    case 0xb8:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->eax = ((uint16_t)imm);
        break;
    case 0xb9:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->ecx = ((uint16_t)imm);
        break;
    case 0xba:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->edx = ((uint16_t)imm);
        break;
    case 0xbb:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->ebx = ((uint16_t)imm);
        break;
    case 0xbc:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->esp = ((uint16_t)imm);
        break;
    case 0xbd:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->ebp = ((uint16_t)imm);
        break;
    case 0xbe:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->esi = ((uint16_t)imm);
        break;
    case 0xbf:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        *(uint16_t *)&cpu->edi = ((uint16_t)imm);
        break;
# 2245 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0xc0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (8 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (((uint8_t)imm) % 8 != 0)
            {
                int cnt = ((uint8_t)imm) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = ((int8_t) (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;
    case 0xc1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (((uint8_t)imm) % 16 != 0)
            {
                int cnt = ((uint8_t)imm) % 16;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - cnt);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - cnt); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (((uint8_t)imm) % 16 != 0)
            {
                int cnt = ((uint8_t)imm) % 16;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (16 - cnt);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (16 - cnt); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (((uint8_t)imm) % 16 != 0)
            {
                int cnt = ((uint8_t)imm) % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (16 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (((uint8_t)imm) % 16 != 0)
            {
                int cnt = ((uint8_t)imm) % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (((uint8_t)imm) % 16 != 0)
            {
                int cnt = ((uint8_t)imm) % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = ((int16_t)(modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint16_t _val = ((int16_t) (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;

    case 0xc2:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->eip = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        if (16 == 16)
            cpu->eip &= 0xffff;
        cpu->esp += ((uint16_t)imm);
        break;
    case 0xc3:
        __use(0);
        cpu->eip = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        if (16 == 16)
            cpu->eip &= 0xffff;
        cpu->esp += 0;
        break;

    case 0xc9:
        __use(0);
        *(uint16_t *)&cpu->esp = ((uint16_t)cpu->ebp);
        *(uint16_t *)&cpu->ebp = ({ uint16_t val; if (!tlb_read(tlb, cpu->esp, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
        cpu->esp += 16 / 8;
        break;

    case 0xcd:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        return ((uint8_t)imm);
        break;

    case 0xc6:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (modrm.type == modrm_reg)
        {
            (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((uint8_t)imm);
        }
        else
        {
            ({ uint8_t _val = ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;
    case 0xc7:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        if (modrm.type == modrm_reg)
        {
            (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = ((uint16_t)imm);
        }
        else
        {
            ({ uint16_t _val = ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
        }
        (void)0;
        break;

    case 0xd0:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (8 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (1 % 8 != 0)
            {
                int cnt = 1 % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = ((int8_t) (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;
    case 0xd1:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (1 % 16 != 0)
            {
                int cnt = 1 % 16;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - cnt);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - cnt); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (1 % 16 != 0)
            {
                int cnt = 1 % 16;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (16 - cnt);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (16 - cnt); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (1 % 16 != 0)
            {
                int cnt = 1 % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (16 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (1 % 16 != 0)
            {
                int cnt = 1 % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (1 % 16 != 0)
            {
                int cnt = 1 % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = ((int16_t)(modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint16_t _val = ((int16_t) (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;
    case 0xd2:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (8 - cnt); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (8 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (8 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (((uint8_t)cpu->ecx) % 8 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 8;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ((int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint8_t _val = ((int8_t) (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;
    case 0xd3:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            if (((uint8_t)cpu->ecx) % 16 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 16;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - cnt);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt | (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - cnt); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1;
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                }
            };
            break;
        case 1:
            __use(0);
            if (((uint8_t)cpu->ecx) % 16 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 16;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (16 - cnt);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt | (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (16 - cnt); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (cnt == 1)
                {
                    cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & 1);
                }
            };
            break;
        case 2:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
            break;
        case 4:
        case 6:
            __use(0);
            if (((uint8_t)cpu->ecx) % 16 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << (cnt - 1)) >> (16 - 1);
                cpu->of = cpu->cf ^ ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1));
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt;
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) << cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 5:
            __use(0);
            if (((uint8_t)cpu->ecx) % 16 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (16 - 1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt;
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        case 7:
            __use(0);
            if (((uint8_t)cpu->ecx) % 16 != 0)
            {
                int cnt = ((uint8_t)cpu->ecx) % 16;
                cpu->cf = ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) >> (cnt - 1)) & 1;
                cpu->of = 0;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = ((int16_t)(modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt;
                }
                else
                {
                    ({ uint16_t _val = ((int16_t) (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) >> cnt; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->af = cpu->af_ops = 0;
            };
            break;
        };
        break;

    case 0xd8:
    case 0xd9:
    case 0xda:
    case 0xdb:
    case 0xdc:
    case 0xdd:
    case 0xde:
    case 0xdf:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        if (modrm.type != modrm_reg)
        {
            switch (insn << 4 | modrm.opcode)
            {
            case 0xd80:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd81:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd82:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd83:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->top++;
                break;
            case 0xd84:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd85:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xd86:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xd87:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xd90:
                __use(0);
                ftmp = f80_from_double(({ float val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xd92:
                __use(0);
                ({ float _val = f80_to_double(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xd93:
                __use(0);
                ({ float _val = f80_to_double(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;

            case 0xd95:
                __use(0);
                cpu->fcw = ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; });
                break;

            case 0xd97:
                __use(0);
                ({ uint16_t _val = cpu->fcw; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xda0:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xda1:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xda2:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                break;
            case 0xda3:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                cpu->top++;
                break;
            case 0xda4:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xda5:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xda6:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xda7:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xdb0:
                __use(0);
                ftmp = f80_from_int((int32_t)({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdb2:
                __use(0);
                ({ uint32_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xdb3:
                __use(0);
                ({ uint32_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;
            case 0xdb5:
                __use(0);
                ftmp = ({ float80 val; if (!tlb_read(tlb, addr, &val, 80/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; });
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdb7:
                __use(0);
                ({ float80 _val = cpu->fp[cpu->top + 0]; if (!tlb_write(tlb, addr, &_val, 80/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;
            case 0xdc0:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc1:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc2:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc3:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->top++;
                break;
            case 0xdc4:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc5:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xdc6:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xdc7:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xdd0:
                __use(0);
                ftmp = f80_from_double(({ double val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdd2:
                __use(0);
                ({ double _val = f80_to_double(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xdd3:
                __use(0);
                ({ double _val = f80_to_double(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;

            case 0xde0:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xde1:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xde2:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                break;
            case 0xde3:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                cpu->top++;
                break;
            case 0xde4:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xde5:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xde6:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xde7:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })), cpu->fp[cpu->top + 0]);
                break;
            case 0xdf0:
                __use(0);
                ftmp = f80_from_int((int16_t)({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdf2:
                __use(0);
                ({ uint16_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                break;
            case 0xdf3:
                __use(0);
                ({ uint16_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;
            case 0xdf5:
                __use(0);
                ftmp = f80_from_int((int64_t)({ uint64_t val; if (!tlb_read(tlb, addr, &val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xdf7:
                __use(0);
                ({ uint64_t _val = f80_to_int(cpu->fp[cpu->top + 0]); if (!tlb_write(tlb, addr, &_val, 64/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                cpu->top++;
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            }
        }
        else
        {
            switch (insn << 4 | modrm.opcode)
            {
            case 0xd80:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_add(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd81:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_mul(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd82:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd83:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                break;
            case 0xd84:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd85:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_sub(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xd86:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xd87:
                __use(0);
                cpu->fp[cpu->top + 0] = f80_div(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xd90:
                __use(0);
                ftmp = cpu->fp[cpu->top + modrm.rm_opcode];
                cpu->top--;
                cpu->fp[cpu->top + 0] = ftmp;
                break;
            case 0xd91:
                __use(0);
                float80 ftmp = cpu->fp[cpu->top + 0];
                cpu->fp[cpu->top + 0] = cpu->fp[cpu->top + modrm.rm_opcode];
                cpu->fp[cpu->top + modrm.rm_opcode] = ftmp;
                break;
            case 0xdb5:
                __use(0);
                cpu->zf = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->cf = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->pf = 0;
                cpu->pf_res = 0;
                break;
            case 0xdb6:
                __use(0);
                cpu->zf = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->cf = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->pf = 0;
                cpu->pf_res = 0;
                break;
            case 0xdc0:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_add(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xdc1:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_mul(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xdc4:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_sub(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xdc5:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_sub(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xdc6:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_div(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xdc7:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_div(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                break;
            case 0xdd0:
                __use(0);
                break;
            case 0xdd3:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = cpu->fp[cpu->top + 0];
                cpu->top++;
                break;
            case 0xdd4:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                break;
            case 0xdd5:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                break;
            case 0xda5:
                __use(0);
                cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->c1 = 0;
                cpu->c2 = 0;
                cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                cpu->top++;
                break;
            case 0xde0:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_add(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                cpu->top++;
                break;
            case 0xde1:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_mul(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                cpu->top++;
                break;
            case 0xde4:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_sub(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                break;
            case 0xde5:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_sub(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                cpu->top++;
                break;
            case 0xde6:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_div(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->top++;
                break;
            case 0xde7:
                __use(0);
                cpu->fp[cpu->top + modrm.rm_opcode] = f80_div(cpu->fp[cpu->top + modrm.rm_opcode], cpu->fp[cpu->top + 0]);
                cpu->top++;
                break;
            case 0xdf0:
                __use(0);
                cpu->top++;
                break;
            case 0xdf5:
                __use(0);
                cpu->zf = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->cf = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->pf = 0;
                cpu->pf_res = 0;
                cpu->top++;
                break;
            case 0xdf6:
                __use(0);
                cpu->zf = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->cf = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                cpu->pf = 0;
                cpu->pf_res = 0;
                cpu->top++;
                break;
            default:
                switch (insn << 8 | modrm.opcode << 4 | modrm.rm_opcode)
                {
                case 0xd940:
                    __use(0);
                    cpu->fp[cpu->top + 0] = f80_neg(cpu->fp[cpu->top + 0]);
                    break;
                case 0xd941:
                    __use(0);
                    cpu->fp[cpu->top + 0] = f80_abs(cpu->fp[cpu->top + 0]);
                    break;
                case 0xd944:
                    __use(0);
                    cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], fpu_consts[fconst_zero]);
                    cpu->c1 = 0;
                    cpu->c2 = 0;
                    cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], fpu_consts[fconst_zero]);
                    break;
                case 0xd945:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;
                case 0xd950:
                    __use(0);
                    ftmp = fpu_consts[fconst_one];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd951:
                    __use(0);
                    ftmp = fpu_consts[fconst_log2t];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd952:
                    __use(0);
                    ftmp = fpu_consts[fconst_log2e];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd953:
                    __use(0);
                    ftmp = fpu_consts[fconst_pi];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd954:
                    __use(0);
                    ftmp = fpu_consts[fconst_log2];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd955:
                    __use(0);
                    ftmp = fpu_consts[fconst_ln2];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd956:
                    __use(0);
                    ftmp = fpu_consts[fconst_zero];
                    cpu->top--;
                    cpu->fp[cpu->top + 0] = ftmp;
                    break;
                case 0xd960:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;
                case 0xd961:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;

                case 0xd970:
                    __use(0);
                    cpu->fp[cpu->top + 0] = f80_mod(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + 1]);
                    break;
                case 0xd972:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;
                case 0xd974:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;
                case 0xd975:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                    break;

                case 0xde31:
                    __use(0);
                    cpu->c0 = f80_lt(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                    cpu->c1 = 0;
                    cpu->c2 = 0;
                    cpu->c3 = f80_eq(cpu->fp[cpu->top + 0], cpu->fp[cpu->top + modrm.rm_opcode]);
                    cpu->top++;
                    cpu->top++;
                    break;
                case 0xdf40:
                    __use(0);
                    *(uint16_t *)&cpu->eax = cpu->fsw;
                    break;
                default:
                    __use(0);
                    {
                        cpu->eip = saved_ip;
                        return 6;
                    };
                }
            }
        }
        break;

    case 0xe3:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        if (((uint16_t)cpu->ecx) == 0)
        {
            cpu->eip += ((uint16_t)imm);
            if (16 == 16)
                cpu->eip &= 0xffff;
        };
        break;

    case 0xe8:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        ({ uint16_t _val = cpu->eip; if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
        cpu->esp -= 16 / 8;
        cpu->eip += ((uint16_t)imm);
        if (16 == 16)
            cpu->eip &= 0xffff;
        ;
        break;

    case 0xe9:
        __use(0);
        imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 16 / 8;
        __use(0, (long long)imm);
        cpu->eip += ((uint16_t)imm);
        if (16 == 16)
            cpu->eip &= 0xffff;
        ;
        break;
    case 0xeb:
        __use(0);
        imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, (long long)imm);
        imm = (int8_t)(uint8_t)imm;
        cpu->eip += ((uint16_t)imm);
        if (16 == 16)
            cpu->eip &= 0xffff;
        ;
        break;

    case 0xf0:
    lockrestart:
        insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, insn);
        switch (insn)
        {
        case 0x65:
            __use(0);
            addr += cpu->tls_ptr;
            goto lockrestart;

        case 0x66:

            goto lockrestart;
# 2440 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0x00 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x00 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x08 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x08 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x10 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == ((uint8_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == (uint8_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x10 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) == ((uint16_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) == (uint16_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x18 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == ((uint8_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) == (uint8_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x18 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) == ((uint16_t)-1) / 2);
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) == (uint16_t)-1);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x20 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x20 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x28 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x28 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
        case 0x30 + 0x0:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
            }
            else
            {
                ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 0x30 + 0x1:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
            }
            else
            {
                ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
# 2462 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0x80:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                cpu->op1 = ((uint8_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 1:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint8_t)imm);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 2:
                __use(0);
                cpu->op1 = ((uint8_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 3:
                __use(0);
                cpu->op1 = ((uint8_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm) + cpu->cf), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == ((uint8_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm) + cpu->cf), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; }) || (cpu->cf && ((uint8_t)imm) == (uint8_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 4:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t)imm);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 5:
                __use(0);
                cpu->op1 = ((uint8_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) imm)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) imm)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 6:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint8_t)imm);
                }
                else
                {
                    ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint8_t) imm); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;
        case 0x81:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                cpu->op1 = ((uint16_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 1:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint16_t)imm);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 2:
                __use(0);
                cpu->op1 = ((uint16_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 3:
                __use(0);
                cpu->op1 = ((uint16_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 4:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t)imm);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 5:
                __use(0);
                cpu->op1 = ((uint16_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 6:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint16_t)imm);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;
        case 0x83:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                cpu->op1 = ((uint16_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 1:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint16_t)imm);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 2:
                __use(0);
                cpu->op1 = ((uint16_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 3:
                __use(0);
                cpu->op1 = ((uint16_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm) + cpu->cf), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == ((uint16_t)-1) / 2);
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm) + cpu->cf), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; }) || (cpu->cf && ((uint16_t)imm) == (uint16_t)-1);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 4:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t)imm);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 5:
                __use(0);
                cpu->op1 = ((uint16_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) imm)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) imm)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 6:
                __use(0);
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint16_t)imm);
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ ((uint16_t) imm); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;

        case 0x0f:
            insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, insn);
            switch (insn)
            {
            case 0xab:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16));
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            case 0xb3:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16));
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
            case 0xbb:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16))) ? 1 : 0;
                ;
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << ((*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) % 16));
                }
                else
                {
                    ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                break;
# 2488 "/Users/bbarrows/repos/ish2/emu/interp.c"
            case 0xba:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
                cpu->eip += 8 / 8;
                __use(0, (long long)imm);
                imm = (int8_t)(uint8_t)imm;
                switch (modrm.opcode)
                {
                case 5:
                    __use(0);
                    cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + ((uint16_t) imm) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint16_t) imm) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint16_t)imm) % 16))) ? 1 : 0;
                    ;
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << (((uint16_t)imm) % 16));
                    }
                    else
                    {
                        ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) | (1 << (((uint16_t) imm) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    break;
                case 6:
                    __use(0);
                    cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + ((uint16_t) imm) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint16_t) imm) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint16_t)imm) % 16))) ? 1 : 0;
                    ;
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << (((uint16_t)imm) % 16));
                    }
                    else
                    {
                        ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ~(1 << (((uint16_t) imm) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    break;
                case 7:
                    __use(0);
                    cpu->cf = (((modrm.type != modrm_reg) ? ({ uint16_t val; if (!tlb_read(tlb, addr + ((uint16_t) imm) / 16 * (16/8), &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr + ((uint16_t) imm) / 16 * (16/8); return 13; } val; }) : (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))) & (1 << (((uint16_t)imm) % 16))) ? 1 : 0;
                    ;
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << (((uint16_t)imm) % 16));
                    }
                    else
                    {
                        ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) ^ (1 << (((uint16_t) imm) % 16)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    break;
                default:
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                };
                break;

            case 0xb0:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                if (modrm.type == modrm_reg)
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                cpu->op1 = ((uint8_t)cpu->eax);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                {
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                    }
                    else
                    {
                        ({ uint8_t _val = (*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id)); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                }
                else
                    *(uint8_t *)&cpu->eax = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                break;
            case 0xb1:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                if (modrm.type == modrm_reg)
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                cpu->op1 = ((uint16_t)cpu->eax);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (((uint16_t) cpu->eax)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (((uint16_t) cpu->eax)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                {
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
                    }
                    else
                    {
                        ({ uint16_t _val = (*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id)); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                }
                else
                    *(uint16_t *)&cpu->eax = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                break;

            case 0xc0:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                if (modrm.type == modrm_reg)
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                do
                {
                    dword_t tmp = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                    (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id)) = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = tmp;
                    }
                    else
                    {
                        ({ uint8_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                } while (0);
                cpu->op1 = (*(uint8_t *)(((char *)cpu) + (modrm_regptr).reg8_id));
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) ((*(uint8_t *) (((char *) cpu) + (modrm_regptr).reg8_id))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 0xc1:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                if (modrm.type == modrm_reg)
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                do
                {
                    dword_t tmp = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
                    (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = tmp;
                    }
                    else
                    {
                        ({ uint16_t _val = tmp; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                } while (0);
                cpu->op1 = (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id));
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) ((*(uint16_t *) (((char *) cpu) + (modrm_regptr).reg16_id))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;

            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            }
            break;
# 2519 "/Users/bbarrows/repos/ish2/emu/interp.c"
        case 0xfe:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                do
                {
                    int tmp = cpu->cf;
                    cpu->op1 = 1;
                    cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    cpu->af_ops = 1;
                    cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (1), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                    cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (1), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                    }
                    else
                    {
                        ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                    cpu->cf = tmp;
                } while (0);
                break;
            case 1:
                __use(0);
                do
                {
                    int tmp = cpu->cf;
                    cpu->op1 = 1;
                    cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    cpu->af_ops = 1;
                    cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (1), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                    cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (1), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                    }
                    else
                    {
                        ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                    cpu->cf = tmp;
                } while (0);
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;
        case 0xff:
            __use(0);
            if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
            {
                cpu->segfault_addr = cpu->eip;
                cpu->eip = saved_ip;
                return 13;
            };
            if (modrm.type == modrm_reg)
            {
                cpu->eip = saved_ip;
                return 6;
            };
            switch (modrm.opcode)
            {
            case 0:
                __use(0);
                do
                {
                    int tmp = cpu->cf;
                    cpu->op1 = 1;
                    cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    cpu->af_ops = 1;
                    cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                    cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                    }
                    else
                    {
                        ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                    cpu->cf = tmp;
                } while (0);
                break;
            case 1:
                __use(0);
                do
                {
                    int tmp = cpu->cf;
                    cpu->op1 = 1;
                    cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                    cpu->af_ops = 1;
                    cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                    cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                    if (modrm.type == modrm_reg)
                    {
                        (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                    }
                    else
                    {
                        ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                    }
                    (void)0;
                    cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                    cpu->cf = tmp;
                } while (0);
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            };
            break;

        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        }
        break;

    case 0xf2:
        insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, insn);
        switch (insn)
        {
        case 0x0f:
            insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, insn);
            switch (insn)
            {

            case 0x11:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                break;

            case 0x18 ... 0x1f:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                break;
            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            }
            break;

        case 0xa6:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->esi += 8 / 8;
                else
                    cpu->esi -= 8 / 8;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xa7:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->op2 = ({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->esi += 16 / 8;
                else
                    cpu->esi -= 16 / 8;
                if (!cpu->df)
                    cpu->edi += 16 / 8;
                else
                    cpu->edi -= 16 / 8;
                cpu->ecx--;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xae:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ((uint8_t)cpu->eax);
                cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xaf:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ((uint16_t)cpu->eax);
                cpu->op2 = ({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint16_t) (((uint16_t) cpu->eax)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int16_t) (((uint16_t) cpu->eax)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->edi += 16 / 8;
                else
                    cpu->edi -= 16 / 8;
                cpu->ecx--;
                if ((cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        }
        break;

    case 0xf3:
        insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
        cpu->eip += 8 / 8;
        __use(0, insn);
        switch (insn)
        {
        case 0x0f:

            insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, insn);
            switch (insn)
            {

            case 0x11:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
                break;

            case 0x18 ... 0x1f:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                break;

            case 0xbc:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->zf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0;
                cpu->zf_res = 0;
                if (!cpu->zf)
                    (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = __builtin_ctz((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;
            case 0xbd:
                __use(0);
                if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
                {
                    cpu->segfault_addr = cpu->eip;
                    cpu->eip = saved_ip;
                    return 13;
                };
                cpu->zf = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0;
                cpu->zf_res = 0;
                if (!cpu->zf)
                    (*(uint16_t *)(((char *)cpu) + (modrm_regptr).reg16_id)) = 16 - __builtin_clz((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                break;

            default:
                __use(0);
                {
                    cpu->eip = saved_ip;
                    return 6;
                };
            }
            break;

        case 0x90:
            __use(0);
            break;

        case 0xa4:
            __use(0);
            while (cpu->ecx != 0)
            {
                ({ uint8_t _val = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; }); if (!tlb_write(tlb, cpu->edi, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
                if (!cpu->df)
                    cpu->esi += 8 / 8;
                else
                    cpu->esi -= 8 / 8;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
            };
            break;
        case 0xa5:
            __use(0);
            while (cpu->ecx != 0)
            {
                ({ uint16_t _val = ({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; }); if (!tlb_write(tlb, cpu->edi, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
                if (!cpu->df)
                    cpu->esi += 16 / 8;
                else
                    cpu->esi -= 16 / 8;
                if (!cpu->df)
                    cpu->edi += 16 / 8;
                else
                    cpu->edi -= 16 / 8;
                cpu->ecx--;
            };
            break;
        case 0xa6:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->esi += 8 / 8;
                else
                    cpu->esi -= 8 / 8;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
                if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xa7:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->op2 = ({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; })), (int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->esi += 16 / 8;
                else
                    cpu->esi -= 16 / 8;
                if (!cpu->df)
                    cpu->edi += 16 / 8;
                else
                    cpu->edi -= 16 / 8;
                cpu->ecx--;
                if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xaa:
            __use(0);
            while (cpu->ecx != 0)
            {
                ({ uint8_t _val = ((uint8_t) cpu->eax); if (!tlb_write(tlb, cpu->edi, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
            };
            break;
        case 0xab:
            __use(0);
            while (cpu->ecx != 0)
            {
                ({ uint16_t _val = ((uint16_t) cpu->eax); if (!tlb_write(tlb, cpu->edi, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } });
                if (!cpu->df)
                    cpu->edi += 16 / 8;
                else
                    cpu->edi -= 16 / 8;
                cpu->ecx--;
            };
            break;
        case 0xac:
            __use(0);
            while (cpu->ecx != 0)
            {
                *(uint8_t *)&cpu->eax = ({ uint8_t val; if (!tlb_read(tlb, cpu->esi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                if (!cpu->df)
                    cpu->esi += 8 / 8;
                else
                    cpu->esi -= 8 / 8;
                cpu->ecx--;
            };
            break;
        case 0xad:
            __use(0);
            while (cpu->ecx != 0)
            {
                *(uint16_t *)&cpu->eax = ({ uint16_t val; if (!tlb_read(tlb, cpu->esi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esi; return 13; } val; });
                if (!cpu->df)
                    cpu->esi += 16 / 8;
                else
                    cpu->esi -= 16 / 8;
                cpu->ecx--;
            };
            break;
        case 0xae:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ((uint8_t)cpu->eax);
                cpu->op2 = ({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint8_t) (((uint8_t) cpu->eax)), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (({ uint8_t val; if (!tlb_read(tlb, cpu->edi, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int8_t) (((uint8_t) cpu->eax)), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->edi += 8 / 8;
                else
                    cpu->edi -= 8 / 8;
                cpu->ecx--;
                if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;
        case 0xaf:
            __use(0);
            while (cpu->ecx != 0)
            {
                cpu->op1 = ((uint16_t)cpu->eax);
                cpu->op2 = ({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; });
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (uint16_t) (((uint16_t) cpu->eax)), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (({ uint16_t val; if (!tlb_read(tlb, cpu->edi, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->edi; return 13; } val; })), (int16_t) (((uint16_t) cpu->eax)), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                if (!cpu->df)
                    cpu->edi += 16 / 8;
                else
                    cpu->edi -= 16 / 8;
                cpu->ecx--;
                if (!(cpu->zf_res ? cpu->res == 0 : cpu->zf))
                    break;
            };
            break;

        case 0xc3:
            __use(0);
            cpu->eip = ({ uint32_t val; if (!tlb_read(tlb, cpu->esp, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp; return 13; } val; });
            cpu->esp += 16 / 8;
            if (16 == 16)
                cpu->eip &= 0xffff;
            cpu->esp += 0;
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        }
        break;
# 2630 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0xf6:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
        case 1:
            __use(0);
            imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 8 / 8;
            __use(0, (long long)imm);
            imm = (int8_t)(uint8_t)imm;
            cpu->res = (int32_t)(int8_t)((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint8_t)imm));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            break;
        case 2:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = ~(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            }
            else
            {
                ({ uint8_t _val = ~(modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })); if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 3:
            __use(0);
            cpu->op1 = 0;
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) (0), (int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) (0), (uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
            }
            else
            {
                ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
            break;
        case 4:
            __use(0);
            do
            {
                uint64_t tmp = ((uint8_t)cpu->eax) * (uint64_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint8_t *)&cpu->eax = tmp;
                *(uint8_t *)&cpu->edx = tmp >> 8;
                ;
                cpu->cf = cpu->of = (tmp != (uint32_t)tmp);
                cpu->af = cpu->af_ops = 0;
                cpu->zf = cpu->sf = cpu->pf = cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
            } while (0);
            break;
        case 5:
            __use(0);
            do
            {
                int64_t tmp = (int64_t)(int8_t)((uint8_t)cpu->eax) * (int8_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint8_t *)&cpu->eax = tmp;
                *(uint8_t *)&cpu->edx = tmp >> 8;
                cpu->cf = cpu->of = (tmp != (int32_t)tmp);
                cpu->zf = cpu->sf = cpu->pf = cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
            } while (0);
            break;
        case 6:
            __use(0);
            do
            {
                if ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0)
                    return 0;
                uint16_t dividend = ((uint8_t)cpu->eax) | ((uint16_t)((uint8_t)cpu->edx) << 8);
                *(uint8_t *)&cpu->edx = dividend % (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint8_t *)&cpu->eax = dividend / (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            } while (0);
            break;
        case 7:
            __use(0);
            do
            {
                if ((modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0)
                    return 0;
                int16_t dividend = ((uint8_t)cpu->eax) | ((int16_t)((uint8_t)cpu->edx) << 8);
                *(uint8_t *)&cpu->edx = dividend % (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint8_t *)&cpu->eax = dividend / (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            } while (0);
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;
    case 0xf7:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
        case 1:
            __use(0);
            imm = ({ uint16_t val; if (!tlb_read(tlb, cpu->eip, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
            cpu->eip += 16 / 8;
            __use(0, (long long)imm);
            cpu->res = (int32_t)(int16_t)((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) & ((uint16_t)imm));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            break;
        case 2:
            __use(0);
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = ~(modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            }
            else
            {
                ({ uint16_t _val = ~(modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })); if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            break;
        case 3:
            __use(0);
            cpu->op1 = 0;
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
            cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) (0), (int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) (0), (uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
            if (modrm.type == modrm_reg)
            {
                (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
            }
            else
            {
                ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
            }
            (void)0;
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
            ;
            break;
        case 4:
            __use(0);
            do
            {
                uint64_t tmp = ((uint16_t)cpu->eax) * (uint64_t)(modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint16_t *)&cpu->eax = tmp;
                *(uint16_t *)&cpu->edx = tmp >> 16;
                ;
                cpu->cf = cpu->of = (tmp != (uint32_t)tmp);
                cpu->af = cpu->af_ops = 0;
                cpu->zf = cpu->sf = cpu->pf = cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
            } while (0);
            break;
        case 5:
            __use(0);
            do
            {
                int64_t tmp = (int64_t)(int16_t)((uint16_t)cpu->eax) * (int16_t)(modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint16_t *)&cpu->eax = tmp;
                *(uint16_t *)&cpu->edx = tmp >> 16;
                cpu->cf = cpu->of = (tmp != (int32_t)tmp);
                cpu->zf = cpu->sf = cpu->pf = cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
            } while (0);
            break;
        case 6:
            __use(0);
            do
            {
                if ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0)
                    return 0;
                uint32_t dividend = ((uint16_t)cpu->eax) | ((uint32_t)((uint16_t)cpu->edx) << 16);
                *(uint16_t *)&cpu->edx = dividend % (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint16_t *)&cpu->eax = dividend / (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            } while (0);
            break;
        case 7:
            __use(0);
            do
            {
                if ((modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })) == 0)
                    return 0;
                int32_t dividend = ((uint16_t)cpu->eax) | ((int32_t)((uint16_t)cpu->edx) << 16);
                *(uint16_t *)&cpu->edx = dividend % (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                *(uint16_t *)&cpu->eax = dividend / (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            } while (0);
            break;
        default:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;

    case 0xfc:
        __use(0);
        cpu->df = 0;
        break;
    case 0xfd:
        __use(0);
        cpu->df = 1;
        break;
# 2657 "/Users/bbarrows/repos/ish2/emu/interp.c"
    case 0xfe:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            do
            {
                int tmp = cpu->cf;
                cpu->op1 = 1;
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (1), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (1), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->cf = tmp;
            } while (0);
            break;
        case 1:
            __use(0);
            do
            {
                int tmp = cpu->cf;
                cpu->op1 = 1;
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int8_t) (1), (int8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint8_t) ((modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint8_t) (1), (uint8_t *) &cpu->res); cpu->res = (int8_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) = cpu->res;
                }
                else
                {
                    ({ uint8_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->cf = tmp;
            } while (0);
            break;
        case 2:
            __use(0);
            ({ uint16_t _val = cpu->eip; if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
            cpu->esp -= 16 / 8;
            cpu->eip = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (16 == 16)
                cpu->eip &= 0xffff;
            ;
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        case 4:
            __use(0);
            cpu->eip = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (16 == 16)
                cpu->eip &= 0xffff;
            ;
            break;
        case 5:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        case 6:
            __use(0);
            ({ uint8_t _val = (modrm.type == modrm_reg ? (*(uint8_t *) (((char *) cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
            cpu->esp -= 16 / 8;
            break;
        case 7:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;
    case 0xff:
        __use(0);
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
        switch (modrm.opcode)
        {
        case 0:
            __use(0);
            do
            {
                int tmp = cpu->cf;
                cpu->op1 = 1;
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->cf = ({ int ov = __builtin_add_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->of = ({ int ov = __builtin_add_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->cf = tmp;
            } while (0);
            break;
        case 1:
            __use(0);
            do
            {
                int tmp = cpu->cf;
                cpu->op1 = 1;
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                cpu->of = ({ int ov = __builtin_sub_overflow((int16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (int16_t) (1), (int16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                cpu->cf = ({ int ov = __builtin_sub_overflow((uint16_t) ((modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }))), (uint16_t) (1), (uint16_t *) &cpu->res); cpu->res = (int16_t) cpu->res; ov; });
                if (modrm.type == modrm_reg)
                {
                    (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) = cpu->res;
                }
                else
                {
                    ({ uint16_t _val = cpu->res; if (!tlb_write(tlb, addr, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } });
                }
                (void)0;
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                cpu->cf = tmp;
            } while (0);
            break;
        case 2:
            __use(0);
            ({ uint16_t _val = cpu->eip; if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
            cpu->esp -= 16 / 8;
            cpu->eip = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (16 == 16)
                cpu->eip &= 0xffff;
            ;
            break;
        case 3:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        case 4:
            __use(0);
            cpu->eip = (modrm.type == modrm_reg ? (*(uint16_t *)(((char *)cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (16 == 16)
                cpu->eip &= 0xffff;
            ;
            break;
        case 5:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        case 6:
            __use(0);
            ({ uint16_t _val = (modrm.type == modrm_reg ? (*(uint16_t *) (((char *) cpu) + (modrm_base).reg16_id)) : ({ uint16_t val; if (!tlb_read(tlb, addr, &val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })); if (!tlb_write(tlb, cpu->esp - 16/8, &_val, 16/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 16/8; return 13; } });
            cpu->esp -= 16 / 8;
            break;
        case 7:
            __use(0);
            {
                cpu->eip = saved_ip;
                return 6;
            };
        };
        break;

    default:
        __use(0);
        {
            cpu->eip = saved_ip;
            return 6;
        };
    }
    __use(0);
    return -1;
}

static _Bool modrm_compute(struct cpu_state *cpu, struct tlb *tlb, addr_t *addr_out,
                           struct modrm *modrm, struct regptr *modrm_regptr, struct regptr *modrm_base)
{
    if (!modrm_decode32(&cpu->eip, tlb, modrm))
        return 0;
    *modrm_regptr = regptr_from_reg(modrm->reg);
    *modrm_base = regptr_from_reg(modrm->base);
    if (modrm->type == modrm_reg)
        return 1;

    if (modrm->base != reg_none)
        *addr_out += (*(uint32_t *)(((char *)cpu) + (*modrm_base).reg32_id));
    *addr_out += modrm->offset;
    if (modrm->type == modrm_mem_si)
    {
        struct regptr index_reg = regptr_from_reg(modrm->index);
        *addr_out += (*(uint32_t *)(((char *)cpu) + (index_reg).reg32_id)) << modrm->shift;
    }
    return 1;
}

__attribute__((flatten)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory"))) void cpu_run(struct cpu_state *cpu)
{
    int i = 0;
    struct tlb tlb = {.mem = cpu->mem};
    tlb_flush(&tlb);
    pthread_rwlock_rdlock(&cpu->mem->lock);
    int changes = cpu->mem->changes;
    while (1)
    {
        int interrupt = cpu_step32(cpu, &tlb);
        if (interrupt == -1 && i++ >= 100000)
        {
            i = 0;
            interrupt = 32;
        }
        if (interrupt != -1)
        {
            cpu->trapno = interrupt;
            pthread_rwlock_unlock(&cpu->mem->lock);
            handle_interrupt(interrupt);
            pthread_rwlock_rdlock(&cpu->mem->lock);
            if (tlb.mem != cpu->mem)
                tlb.mem = cpu->mem;
            if (cpu->mem->changes != changes)
            {
                tlb_flush(&tlb);
                changes = cpu->mem->changes;
            }
        }
    }
}
