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
#ifndef _I386_USER_H
#define _I386_USER_H

#include <asm/page.h>

struct user_i387_struct {
 long cwd;
 long swd;
 long twd;
 long fip;
 long fcs;
 long foo;
 long fos;
 long st_space[20];
};

struct user_fxsr_struct {
 unsigned short cwd;
 unsigned short swd;
 unsigned short twd;
 unsigned short fop;
 long fip;
 long fcs;
 long foo;
 long fos;
 long mxcsr;
 long reserved;
 long st_space[32];
 long xmm_space[32];
 long padding[56];
};

struct user_regs_struct {
 long ebx, ecx, edx, esi, edi, ebp, eax;
 unsigned short ds, __ds, es, __es;
 unsigned short fs, __fs, gs, __gs;
 long orig_eax, eip;
 unsigned short cs, __cs;
 long eflags, esp;
 unsigned short ss, __ss;
};

struct user{

 struct user_regs_struct regs;

 int u_fpvalid;

 struct user_i387_struct i387;

 unsigned long int u_tsize;
 unsigned long int u_dsize;
 unsigned long int u_ssize;
 unsigned long start_code;
 unsigned long start_stack;
 long int signal;
 int reserved;
 struct user_pt_regs * u_ar0;

 struct user_i387_struct* u_fpstate;
 unsigned long magic;
 char u_comm[32];
 int u_debugreg[8];
};
#define NBPG PAGE_SIZE
#define UPAGES 1
#define HOST_TEXT_START_ADDR (u.start_code)
#define HOST_STACK_END_ADDR (u.start_stack + u.u_ssize * NBPG)

#endif
