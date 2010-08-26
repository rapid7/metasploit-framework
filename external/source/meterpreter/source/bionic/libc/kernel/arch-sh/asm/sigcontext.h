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
#ifndef __ASM_SH_SIGCONTEXT_H
#define __ASM_SH_SIGCONTEXT_H

struct sigcontext {
 unsigned long oldmask;

#ifdef __SH5__

 unsigned long long sc_regs[63];
 unsigned long long sc_tregs[8];
 unsigned long long sc_pc;
 unsigned long long sc_sr;

 unsigned long long sc_fpregs[32];
 unsigned int sc_fpscr;
 unsigned int sc_fpvalid;
#else

 unsigned long sc_regs[16];
 unsigned long sc_pc;
 unsigned long sc_pr;
 unsigned long sc_sr;
 unsigned long sc_gbr;
 unsigned long sc_mach;
 unsigned long sc_macl;

 unsigned long sc_fpregs[16];
 unsigned long sc_xfpregs[16];
 unsigned int sc_fpscr;
 unsigned int sc_fpul;
 unsigned int sc_ownedfp;
#endif
};

#endif
