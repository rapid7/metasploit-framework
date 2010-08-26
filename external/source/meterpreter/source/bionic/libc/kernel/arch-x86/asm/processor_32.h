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
#ifndef __ASM_I386_PROCESSOR_H
#define __ASM_I386_PROCESSOR_H

#include <asm/vm86.h>
#include <asm/math_emu.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/types.h>
#include <asm/sigcontext.h>
#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/system.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <asm/percpu.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <asm/processor-flags.h>

struct desc_struct {
 unsigned long a,b;
};

#define desc_empty(desc)   (!((desc)->a | (desc)->b))

#define desc_equal(desc1, desc2)   (((desc1)->a == (desc2)->a) && ((desc1)->b == (desc2)->b))

#define current_text_addr() ({ void *pc; __asm__("movl $1f,%0\n1:":"=g" (pc)); pc; })

struct cpuinfo_x86 {
 __u8 x86;
 __u8 x86_vendor;
 __u8 x86_model;
 __u8 x86_mask;
 char wp_works_ok;
 char hlt_works_ok;
 char hard_math;
 char rfu;
 int cpuid_level;
 unsigned long x86_capability[NCAPINTS];
 char x86_vendor_id[16];
 char x86_model_id[64];
 int x86_cache_size;
 int x86_cache_alignment;
 char fdiv_bug;
 char f00f_bug;
 char coma_bug;
 char pad0;
 int x86_power;
 unsigned long loops_per_jiffy;
 unsigned char x86_max_cores;
 unsigned char apicid;
 unsigned short x86_clflush_size;
} __attribute__((__aligned__(SMP_CACHE_BYTES)));

#define X86_VENDOR_INTEL 0
#define X86_VENDOR_CYRIX 1
#define X86_VENDOR_AMD 2
#define X86_VENDOR_UMC 3
#define X86_VENDOR_NEXGEN 4
#define X86_VENDOR_CENTAUR 5
#define X86_VENDOR_TRANSMETA 7
#define X86_VENDOR_NSC 8
#define X86_VENDOR_NUM 9
#define X86_VENDOR_UNKNOWN 0xff

#define cpu_data(cpu) boot_cpu_data
#define current_cpu_data boot_cpu_data

#define load_cr3(pgdir) write_cr3(__pa(pgdir))

#define TASK_SIZE (PAGE_OFFSET)

#define TASK_UNMAPPED_BASE (PAGE_ALIGN(TASK_SIZE / 3))

#define HAVE_ARCH_PICK_MMAP_LAYOUT

#define IO_BITMAP_BITS 65536
#define IO_BITMAP_BYTES (IO_BITMAP_BITS/8)
#define IO_BITMAP_LONGS (IO_BITMAP_BYTES/sizeof(long))
#define IO_BITMAP_OFFSET offsetof(struct tss_struct,io_bitmap)
#define INVALID_IO_BITMAP_OFFSET 0x8000
#define INVALID_IO_BITMAP_OFFSET_LAZY 0x9000

struct i387_fsave_struct {
 long cwd;
 long swd;
 long twd;
 long fip;
 long fcs;
 long foo;
 long fos;
 long st_space[20];
 long status;
};

struct i387_fxsave_struct {
 unsigned short cwd;
 unsigned short swd;
 unsigned short twd;
 unsigned short fop;
 long fip;
 long fcs;
 long foo;
 long fos;
 long mxcsr;
 long mxcsr_mask;
 long st_space[32];
 long xmm_space[32];
 long padding[56];
} __attribute__ ((aligned (16)));

struct i387_soft_struct {
 long cwd;
 long swd;
 long twd;
 long fip;
 long fcs;
 long foo;
 long fos;
 long st_space[20];
 unsigned char ftop, changed, lookahead, no_update, rm, alimit;
 struct info *info;
 unsigned long entry_eip;
};

union i387_union {
 struct i387_fsave_struct fsave;
 struct i387_fxsave_struct fxsave;
 struct i387_soft_struct soft;
};

typedef struct {
 unsigned long seg;
} mm_segment_t;

struct thread_struct;

struct i386_hw_tss {
 unsigned short back_link,__blh;
 unsigned long esp0;
 unsigned short ss0,__ss0h;
 unsigned long esp1;
 unsigned short ss1,__ss1h;
 unsigned long esp2;
 unsigned short ss2,__ss2h;
 unsigned long __cr3;
 unsigned long eip;
 unsigned long eflags;
 unsigned long eax,ecx,edx,ebx;
 unsigned long esp;
 unsigned long ebp;
 unsigned long esi;
 unsigned long edi;
 unsigned short es, __esh;
 unsigned short cs, __csh;
 unsigned short ss, __ssh;
 unsigned short ds, __dsh;
 unsigned short fs, __fsh;
 unsigned short gs, __gsh;
 unsigned short ldt, __ldth;
 unsigned short trace, io_bitmap_base;
} __attribute__((packed));

struct tss_struct {
 struct i386_hw_tss x86_tss;

 unsigned long io_bitmap[IO_BITMAP_LONGS + 1];

 unsigned long io_bitmap_max;
 struct thread_struct *io_bitmap_owner;

 unsigned long __cacheline_filler[35];

 unsigned long stack[64];
} __attribute__((packed));

#define ARCH_MIN_TASKALIGN 16

struct thread_struct {

 struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];
 unsigned long esp0;
 unsigned long sysenter_cs;
 unsigned long eip;
 unsigned long esp;
 unsigned long fs;
 unsigned long gs;

 unsigned long debugreg[8];

 unsigned long cr2, trap_no, error_code;

 union i387_union i387;

 struct vm86_struct __user * vm86_info;
 unsigned long screen_bitmap;
 unsigned long v86flags, v86mask, saved_esp0;
 unsigned int saved_fs, saved_gs;

 unsigned long *io_bitmap_ptr;
 unsigned long iopl;

 unsigned long io_bitmap_max;
};

#define INIT_THREAD {   .esp0 = sizeof(init_stack) + (long)&init_stack,   .vm86_info = NULL,   .sysenter_cs = __KERNEL_CS,   .io_bitmap_ptr = NULL,   .fs = __KERNEL_PERCPU,  }

#define INIT_TSS {   .x86_tss = {   .esp0 = sizeof(init_stack) + (long)&init_stack,   .ss0 = __KERNEL_DS,   .ss1 = __KERNEL_CS,   .io_bitmap_base = INVALID_IO_BITMAP_OFFSET,   },   .io_bitmap = { [ 0 ... IO_BITMAP_LONGS] = ~0 },  }

#define start_thread(regs, new_eip, new_esp) do {   __asm__("movl %0,%%gs": :"r" (0));   regs->xfs = 0;   set_fs(USER_DS);   regs->xds = __USER_DS;   regs->xes = __USER_DS;   regs->xss = __USER_DS;   regs->xcs = __USER_CS;   regs->eip = new_eip;   regs->esp = new_esp;  } while (0)

struct task_struct;
struct mm_struct;

#define THREAD_SIZE_LONGS (THREAD_SIZE/sizeof(unsigned long))
#define KSTK_TOP(info)  ({   unsigned long *__ptr = (unsigned long *)(info);   (unsigned long)(&__ptr[THREAD_SIZE_LONGS]);  })

#define task_pt_regs(task)  ({   struct pt_regs *__regs__;   __regs__ = (struct pt_regs *)(KSTK_TOP(task_stack_page(task))-8);   __regs__ - 1;  })

#define KSTK_EIP(task) (task_pt_regs(task)->eip)
#define KSTK_ESP(task) (task_pt_regs(task)->esp)

struct microcode_header {
 unsigned int hdrver;
 unsigned int rev;
 unsigned int date;
 unsigned int sig;
 unsigned int cksum;
 unsigned int ldrver;
 unsigned int pf;
 unsigned int datasize;
 unsigned int totalsize;
 unsigned int reserved[3];
};

struct microcode {
 struct microcode_header hdr;
 unsigned int bits[0];
};

typedef struct microcode microcode_t;
typedef struct microcode_header microcode_header_t;

struct extended_signature {
 unsigned int sig;
 unsigned int pf;
 unsigned int cksum;
};

struct extended_sigtable {
 unsigned int count;
 unsigned int cksum;
 unsigned int reserved[3];
 struct extended_signature sigs[0];
};

#define cpu_relax() rep_nop()
#define paravirt_enabled() 0
#define __cpuid native_cpuid
#define get_debugreg(var, register)   (var) = native_get_debugreg(register)
#define set_debugreg(value, register)   native_set_debugreg(register, value)
#define set_iopl_mask native_set_iopl_mask
#define GENERIC_NOP1 ".byte 0x90\n"
#define GENERIC_NOP2 ".byte 0x89,0xf6\n"
#define GENERIC_NOP3 ".byte 0x8d,0x76,0x00\n"
#define GENERIC_NOP4 ".byte 0x8d,0x74,0x26,0x00\n"
#define GENERIC_NOP5 GENERIC_NOP1 GENERIC_NOP4
#define GENERIC_NOP6 ".byte 0x8d,0xb6,0x00,0x00,0x00,0x00\n"
#define GENERIC_NOP7 ".byte 0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n"
#define GENERIC_NOP8 GENERIC_NOP1 GENERIC_NOP7
#define K8_NOP1 GENERIC_NOP1
#define K8_NOP2 ".byte 0x66,0x90\n" 
#define K8_NOP3 ".byte 0x66,0x66,0x90\n" 
#define K8_NOP4 ".byte 0x66,0x66,0x66,0x90\n" 
#define K8_NOP5 K8_NOP3 K8_NOP2 
#define K8_NOP6 K8_NOP3 K8_NOP3
#define K8_NOP7 K8_NOP4 K8_NOP3
#define K8_NOP8 K8_NOP4 K8_NOP4
#define K7_NOP1 GENERIC_NOP1
#define K7_NOP2 ".byte 0x8b,0xc0\n" 
#define K7_NOP3 ".byte 0x8d,0x04,0x20\n"
#define K7_NOP4 ".byte 0x8d,0x44,0x20,0x00\n"
#define K7_NOP5 K7_NOP4 ASM_NOP1
#define K7_NOP6 ".byte 0x8d,0x80,0,0,0,0\n"
#define K7_NOP7 ".byte 0x8D,0x04,0x05,0,0,0,0\n"
#define K7_NOP8 K7_NOP7 ASM_NOP1
#define P6_NOP1 GENERIC_NOP1
#define P6_NOP2 ".byte 0x66,0x90\n"
#define P6_NOP3 ".byte 0x0f,0x1f,0x00\n"
#define P6_NOP4 ".byte 0x0f,0x1f,0x40,0\n"
#define P6_NOP5 ".byte 0x0f,0x1f,0x44,0x00,0\n"
#define P6_NOP6 ".byte 0x66,0x0f,0x1f,0x44,0x00,0\n"
#define P6_NOP7 ".byte 0x0f,0x1f,0x80,0,0,0,0\n"
#define P6_NOP8 ".byte 0x0f,0x1f,0x84,0x00,0,0,0,0\n"
#define ASM_NOP1 GENERIC_NOP1
#define ASM_NOP2 GENERIC_NOP2
#define ASM_NOP3 GENERIC_NOP3
#define ASM_NOP4 GENERIC_NOP4
#define ASM_NOP5 GENERIC_NOP5
#define ASM_NOP6 GENERIC_NOP6
#define ASM_NOP7 GENERIC_NOP7
#define ASM_NOP8 GENERIC_NOP8
#define ASM_NOP_MAX 8
#define ARCH_HAS_PREFETCH
#define ARCH_HAS_PREFETCH
#define ARCH_HAS_PREFETCHW
#define ARCH_HAS_SPINLOCK_PREFETCH
#define spin_lock_prefetch(x) prefetchw(x)

#define cache_line_size() (boot_cpu_data.x86_cache_alignment)

#endif
