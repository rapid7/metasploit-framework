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
#ifndef _ASMARM_SIGCONTEXT_H
#define _ASMARM_SIGCONTEXT_H

struct sigcontext {
 unsigned long trap_no;
 unsigned long error_code;
 unsigned long oldmask;
 unsigned long arm_r0;
 unsigned long arm_r1;
 unsigned long arm_r2;
 unsigned long arm_r3;
 unsigned long arm_r4;
 unsigned long arm_r5;
 unsigned long arm_r6;
 unsigned long arm_r7;
 unsigned long arm_r8;
 unsigned long arm_r9;
 unsigned long arm_r10;
 unsigned long arm_fp;
 unsigned long arm_ip;
 unsigned long arm_sp;
 unsigned long arm_lr;
 unsigned long arm_pc;
 unsigned long arm_cpsr;
 unsigned long fault_address;
};

#endif
