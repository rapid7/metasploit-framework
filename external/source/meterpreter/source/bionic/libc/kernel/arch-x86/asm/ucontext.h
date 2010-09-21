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
#ifndef __ASM_X86_UCONTEXT_H
#define __ASM_X86_UCONTEXT_H

struct ucontext {
 unsigned long uc_flags;
 struct ucontext *uc_link;
 stack_t uc_stack;
 struct sigcontext uc_mcontext;
 sigset_t uc_sigmask;
};

#endif
