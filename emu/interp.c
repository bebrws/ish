#include "emu/cpu.h"
#include "emu/memory.h"
#include "misc.h"
#include "emu/float80.h"
#include "util/list.h"
#include "util/sync.h"
#include "emu/modrm.h"
#include "debug.h"
#include "emu/tlb.h"
#include "emu/regid.h"


//#include "emu/interp.h"


#include "emu/interrupt.h"
#include "kernel/calls.h"
#include "kernel/task.h"
#include "kernel/mm.h"
#include "kernel/fs.h"
#include "fs/stat.h"

#include "emu/cpuid.h"


#include "fs/dev.h"
#include "fs/fd.h"

#include "util/bits.h"


#include "fs/proc.h"

#include "fs/sockrestart.h"


#include "kernel/errno.h"





#include <unistd.h>
#if defined(__APPLE__) && defined(__aarch64__)
#define __debugbreak() __asm__ __volatile__(            \
"   mov    x0, %x0;    \n" /* pid                */ \
"   mov    x1, #0x11;  \n" /* SIGSTOP            */ \
"   mov    x16, #0x25; \n" /* syscall 37 = kill  */ \
"   svc    #0x80       \n" /* software interrupt */ \
"   mov    x0, x0      \n" /* nop                */ \
::  "r"(getpid())                                   \
:   "x0", "x1", "x16", "memory")
#elif defined(__APPLE__) && defined(__arm__)
#define __debugbreak() __asm__ __volatile__(            \
"   mov    r0, %0;     \n" /* pid                */ \
"   mov    r1, #0x11;  \n" /* SIGSTOP            */ \
"   mov    r12, #0x25; \n" /* syscall 37 = kill  */ \
"   svc    #0x80       \n" /* software interrupt */ \
"   mov    r0, r0      \n" /* nop                */ \
::  "r"(getpid())                                   \
:   "r0", "r1", "r12", "memory")
#elif defined(__APPLE__) && (defined(__i386__) || defined(__x86_64__))
#define __debugbreak() __asm__ __volatile__("int $3; mov %eax, %eax")
#endif

#define DBADDR(addr) if (cpu->eip == addr) { __debugbreak(); /*__builtin_trap();*/ }




#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wtautological-constant-out-of-range-compare"

static _Bool modrm_compute(struct cpu_state *cpu, struct tlb *tlb, addr_t *addr_out,
                           struct modrm *modrm, struct regptr *modrm_regptr, struct regptr *modrm_base);



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


extern int current_pid(void);


//void printState() {
// printk("CPU State\neax: %x ebx: %x ecx: %x edx: %x esi: %x edi: %x ebp: %x esp: %x eip: %x eflags: %x", cpu.eax, cpu.ebx, cpu.ecx, cpu.edx, cpu.esi, cpu.edi, cpu.ebp, cpu.esp, cpu.eip, cpu.eflags);
//
//}

// Cleared out lines correlating source code with 
//   # \d+ "[\/a-zA-Z0-9\.]*"

// __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory")))
int cpu_step32(struct cpu_state *cpu, struct tlb *tlb)
{
    
    
    dword_t addr_offset = 0;
    dword_t saved_ip = cpu->eip;
    struct regptr modrm_regptr, modrm_base;
    dword_t addr = 0;
    union xmm_reg xmm_src;
    union xmm_reg xmm_dst;
    float80 ftmp;
    ;

    byte_t insn;
    uint64_t imm = 0;
    struct modrm modrm;

restart:
    
    printk("\nP:%d eax: %x ebx: %x ecx: %x edx: %x esi: %x edi: %x ebp: %x esp: %x eip: %x eflags: %x res: %x\n", current->pid,  cpu->eax, cpu->ebx, cpu->ecx, cpu->edx, cpu->esi, cpu->edi, cpu->ebp, cpu->esp, cpu->eip, cpu->eflags, cpu->res);
    printk("\nP:%d cf_bit %d pf %d af %d zf %d sf %d tf %d if_ %d df %d of_bit %d iopl %d pf_res %d sf_res %d af_ops %d\n", current->pid, cpu->cf_bit, cpu->pf, cpu->af, cpu->zf, cpu->sf, cpu->tf, cpu->if_, cpu->df, cpu->of_bit, cpu->iopl, cpu->pf_res, cpu->sf_res, cpu->af_ops);
    
    insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
    printk("P:%d EIP: %x Op: %x\n", current->pid, cpu->eip, insn);
    // printk("\nEIP is: %x\n", cpu->eip);
    cpu->eip += 8 / 8;
    __use(0, insn);

    switch (insn)
    {


// This is ADD Brad http://ref.x86asm.net/coder32.html#x00   BEBFreg_count
            
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
                
            if (modrm.type == modrm_reg) printk("ADD Reg %s", reg32_name(modrm.reg)); else printk("ADD Addr 0x%x", addr);
                
            cpu->cf = (
                       {
                        int ov = __builtin_add_overflow((uint32_t) ((modrm.type == modrm_reg ?
                            (*(uint32_t *) (((char *) cpu) + (modrm_base).reg32_id)) :
                            ({ uint32_t val;
                               if (!tlb_read(tlb, addr, &val, 32/8)) {
                                   cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13;
                                   
                               }
                               val;
                            
                            }))),
                            (uint32_t) (((uint32_t) imm)), (uint32_t *) &cpu->res);
                             cpu->res = (int32_t) cpu->res;
                              ov;
                
                           });
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
                if (modrm.type == modrm_reg) printk("OR Reg %s", reg32_name(modrm.reg)); else printk("OR Addr 0x%x", addr);
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 2:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
                
                if (modrm.type == modrm_reg) printk("ADC Reg %s", reg32_name(modrm.reg)); else printk("ADC Addr 0x%x", addr);
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
                
                if (modrm.type == modrm_reg) printk("SBB Reg %s", reg32_name(modrm.reg)); else printk("SBB Addr 0x%x", addr);
                
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
                if (modrm.type == modrm_reg) printk("AND Reg %s", reg32_name(modrm.reg)); else printk("AND Addr 0x%x", addr);
                
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
                if (modrm.type == modrm_reg) printk("SUB Reg %s", reg32_name(modrm.reg)); else printk("SUB Addr 0x%x", addr);
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
                if (modrm.type == modrm_reg) printk("XOR Reg %s", reg32_name(modrm.reg)); else printk("XOR Addr 0x%x", addr);
            cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
            cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
            cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
            break;
        case 7:
            __use(0);
            cpu->op1 = ((uint32_t)imm);
            cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            cpu->af_ops = 1;
                if (modrm.type == modrm_reg) printk("C sysMP Reg %s", reg32_name(modrm.reg)); else printk("CMP Addr 0x%x", addr);
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
            
        DBADDR(0xf7fc341a + 1)
            
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
    case 0x8b: // mov
        __use(0);
//            DBADDR(0xf7fc3421 + 1)
        if (!modrm_compute(cpu, tlb, &addr, &modrm, &modrm_regptr, &modrm_base))
        {
            cpu->segfault_addr = cpu->eip;
            cpu->eip = saved_ip;
            return 13;
        };
            uint32_t valTemp; tlb_read(tlb, addr, &valTemp, 32/8);
            printk("0x8b MOV PRE [%x] = %x\n", addr, valTemp);
        (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
            if (modrm.type == modrm_reg) {
                printk("0x8b MOV %s, %s\n", reg32_name(modrm.reg), reg32_name(modrm.base));
            } else {
                printk("0x8b MOV %s, [%x] = %x\n", reg32_name(modrm.reg), addr, (*(uint32_t *)(((char *)cpu) + (modrm_regptr).reg32_id)) );
            }
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
                    
                    if (modrm.type == modrm_reg) printk("ADD Reg %s", reg32_name(modrm.reg)); else printk("ADD Addr 0x%x", addr);
                    
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
                    
                if (modrm.type == modrm_reg) printk("OR Reg %s", reg32_name(modrm.reg)); else printk("OR Addr 0x%x", addr);
                    
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 2:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                    
                if (modrm.type == modrm_reg) printk("ADC Reg %s", reg32_name(modrm.reg)); else printk("ADC Addr 0x%x", addr);
                    
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
                    
                    if (modrm.type == modrm_reg) printk("SBB Reg %s", reg32_name(modrm.reg)); else printk("SBB Addr 0x%x", addr);
                    
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
                    
                if (modrm.type == modrm_reg) printk("AND Reg %s", reg32_name(modrm.reg)); else printk("AND Addr 0x%x", addr);
                    
                cpu->cf = cpu->of = cpu->af = cpu->af_ops = 0;
                cpu->res = (int32_t)(int32_t)((modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; })));
                cpu->zf_res = cpu->sf_res = cpu->pf_res = 1;
                break;
            case 5:
                __use(0);
                cpu->op1 = ((uint32_t)imm);
                cpu->op2 = (modrm.type == modrm_reg ? (*(uint32_t *)(((char *)cpu) + (modrm_base).reg32_id)) : ({ uint32_t val; if (!tlb_read(tlb, addr, &val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return 13; } val; }));
                cpu->af_ops = 1;
                    
                if (modrm.type == modrm_reg) printk("SUB Reg %s", reg32_name(modrm.reg)); else printk("SUB Addr 0x%x", addr);
                    
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
                    
                if (modrm.type == modrm_reg) printk("XOR Reg %s", reg32_name(modrm.reg)); else printk("XOR Addr 0x%x", addr);
                    
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

    byte_t insn;
    uint64_t imm = 0;
    struct modrm modrm;

restart:

    insn = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
    cpu->eip += 8 / 8;
    __use(0, insn);

    switch (insn)
    {

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

//__attribute__((flatten)) __attribute__((no_sanitize("address", "thread", "undefined", "leak", "memory")))
void cpu_run(struct cpu_state *cpu)
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
