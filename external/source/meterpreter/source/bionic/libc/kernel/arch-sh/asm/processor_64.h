/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef __ASM_SH_PROCESSOR_64_H
#define __ASM_SH_PROCESSOR_64_H

#ifndef __ASSEMBLY__

#include <linux/compiler.h>
#include <asm/page.h>
#include <asm/types.h>
#include <asm/cache.h>
#include <asm/ptrace.h>
#include <cpu/registers.h>

#define current_text_addr() ({  void *pc;  unsigned long long __dummy = 0;  __asm__("gettr	tr0, %1\n\t"   "pta	4, tr0\n\t"   "gettr	tr0, %0\n\t"   "ptabs	%1, tr0\n\t"   :"=r" (pc), "=r" (__dummy)   : "1" (__dummy));  pc; })

struct tlb_info {
 unsigned long long next;
 unsigned long long first;
 unsigned long long last;

 unsigned int entries;
 unsigned int step;

 unsigned long flags;
};

struct sh_cpuinfo {
 enum cpu_type type;
 unsigned long loops_per_jiffy;
 unsigned long asid_cache;

 unsigned int cpu_clock, master_clock, bus_clock, module_clock;

 struct cache_info icache;
 struct cache_info dcache;
 struct cache_info scache;

 struct tlb_info itlb;
 struct tlb_info dtlb;

 unsigned long flags;
};

#define boot_cpu_data cpu_data[0]
#define current_cpu_data cpu_data[smp_processor_id()]
#define raw_current_cpu_data cpu_data[raw_smp_processor_id()]

#endif

#define TASK_SIZE 0x7ffff000UL

#define STACK_TOP TASK_SIZE
#define STACK_TOP_MAX STACK_TOP

#define TASK_UNMAPPED_BASE (TASK_SIZE / 3)

#define SR_MMU 0x80000000

#define SR_IMASK 0x000000f0
#define SR_FD 0x00008000
#define SR_SSTEP 0x08000000

#ifndef __ASSEMBLY__

struct sh_fpu_hard_struct {
 unsigned long fp_regs[64];
 unsigned int fpscr;

};

union sh_fpu_union {
 struct sh_fpu_hard_struct hard;

 unsigned long long alignment_dummy;
};

struct thread_struct {
 unsigned long sp;
 unsigned long pc;

 struct pt_regs *kregs;

 struct pt_regs *uregs;

 unsigned long trap_no, error_code;
 unsigned long address;

 union sh_fpu_union fpu;
};

#define INIT_MMAP  { &init_mm, 0, 0, NULL, PAGE_SHARED, VM_READ | VM_WRITE | VM_EXEC, 1, NULL, NULL }

#define INIT_THREAD {   .sp = sizeof(init_stack) +   (long) &init_stack,   .pc = 0,   .kregs = &fake_swapper_regs,   .uregs = NULL,   .trap_no = 0,   .error_code = 0,   .address = 0,   .fpu = { { { 0, } }, }  }

#define SR_USER (SR_MMU | SR_FD)

#define start_thread(regs, new_pc, new_sp)   set_fs(USER_DS);   regs->sr = SR_USER;     regs->pc = new_pc - 4;     regs->pc |= 1;     regs->regs[18] = 0;   regs->regs[15] = new_sp

struct task_struct;
struct mm_struct;

#define copy_segments(p, mm) do { } while (0)
#define release_segments(mm) do { } while (0)
#define forget_segments() do { } while (0)
#define prepare_to_copy(tsk) do { } while (0)

#define FPSCR_INIT 0x00000000

#define thread_saved_pc(tsk) (tsk->thread.pc)

#define KSTK_EIP(tsk) ((tsk)->thread.pc)
#define KSTK_ESP(tsk) ((tsk)->thread.sp)

#define cpu_relax() barrier()

#endif
#endif
