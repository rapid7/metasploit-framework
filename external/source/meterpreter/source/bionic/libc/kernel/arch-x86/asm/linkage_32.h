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
#ifndef __ASM_LINKAGE_H
#define __ASM_LINKAGE_H

#define asmlinkage CPP_ASMLINKAGE __attribute__((regparm(0)))
#define FASTCALL(x) x __attribute__((regparm(3)))
#define fastcall __attribute__((regparm(3)))

#define prevent_tail_call(ret) __asm__ ("" : "=r" (ret) : "0" (ret))

#endif
