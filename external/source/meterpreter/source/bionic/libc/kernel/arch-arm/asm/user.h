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
#ifndef _ARM_USER_H
#define _ARM_USER_H

#include <asm/page.h>
#include <asm/ptrace.h>

struct user_fp {
 struct fp_reg {
 unsigned int sign1:1;
 unsigned int unused:15;
 unsigned int sign2:1;
 unsigned int exponent:14;
 unsigned int j:1;
 unsigned int mantissa1:31;
 unsigned int mantissa0:32;
 } fpregs[8];
 unsigned int fpsr:32;
 unsigned int fpcr:32;
 unsigned char ftype[8];
 unsigned int init_flag;
};

struct user{

 struct pt_regs regs;

 int u_fpvalid;

 unsigned long int u_tsize;
 unsigned long int u_dsize;
 unsigned long int u_ssize;
 unsigned long start_code;
 unsigned long start_stack;
 long int signal;
 int reserved;
 struct pt_regs * u_ar0;

 unsigned long magic;
 char u_comm[32];
 int u_debugreg[8];
 struct user_fp u_fp;
 struct user_fp_struct * u_fp0;

};
#define NBPG PAGE_SIZE
#define UPAGES 1
#define HOST_TEXT_START_ADDR (u.start_code)
#define HOST_STACK_END_ADDR (u.start_stack + u.u_ssize * NBPG)

#endif
