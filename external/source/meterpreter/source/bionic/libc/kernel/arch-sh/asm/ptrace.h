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
#ifndef __ASM_SH_PTRACE_H
#define __ASM_SH_PTRACE_H

#ifdef __SH5__
struct pt_regs {
 unsigned long long pc;
 unsigned long long sr;
 unsigned long long syscall_nr;
 unsigned long long regs[63];
 unsigned long long tregs[8];
 unsigned long long pad[2];
};
#else

#define REG_REG0 0
#define REG_REG15 15

#define REG_PC 16

#define REG_PR 17
#define REG_SR 18
#define REG_GBR 19
#define REG_MACH 20
#define REG_MACL 21

#define REG_SYSCALL 22

#define REG_FPREG0 23
#define REG_FPREG15 38
#define REG_XFREG0 39
#define REG_XFREG15 54

#define REG_FPSCR 55
#define REG_FPUL 56

struct pt_regs {
 unsigned long regs[16];
 unsigned long pc;
 unsigned long pr;
 unsigned long sr;
 unsigned long gbr;
 unsigned long mach;
 unsigned long macl;
 long tra;
};

struct pt_dspregs {
 unsigned long a1;
 unsigned long a0g;
 unsigned long a1g;
 unsigned long m0;
 unsigned long m1;
 unsigned long a0;
 unsigned long x0;
 unsigned long x1;
 unsigned long y0;
 unsigned long y1;
 unsigned long dsr;
 unsigned long rs;
 unsigned long re;
 unsigned long mod;
};

#define PTRACE_GETFDPIC 31  

#define PTRACE_GETFDPIC_EXEC 0  
#define PTRACE_GETFDPIC_INTERP 1  

#define PTRACE_GETDSPREGS 55
#define PTRACE_SETDSPREGS 56
#endif

#endif
