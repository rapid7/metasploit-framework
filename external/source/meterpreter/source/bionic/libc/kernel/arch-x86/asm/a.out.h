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
#ifndef _ASM_X86_A_OUT_H
#define _ASM_X86_A_OUT_H

struct exec
{
 unsigned int a_info;
 unsigned a_text;
 unsigned a_data;
 unsigned a_bss;
 unsigned a_syms;
 unsigned a_entry;
 unsigned a_trsize;
 unsigned a_drsize;
};

#define N_TRSIZE(a) ((a).a_trsize)
#define N_DRSIZE(a) ((a).a_drsize)
#define N_SYMSIZE(a) ((a).a_syms)

#endif
