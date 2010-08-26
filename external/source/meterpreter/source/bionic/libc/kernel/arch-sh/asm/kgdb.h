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
#ifndef __KGDB_H
#define __KGDB_H

#include <asm/ptrace.h>

struct kgdb_regs {
 unsigned long regs[16];
 unsigned long pc;
 unsigned long pr;
 unsigned long sr;
 unsigned long gbr;
 unsigned long mach;
 unsigned long macl;
 unsigned long vbr;
};

typedef void (kgdb_debug_hook_t)(struct pt_regs *regs);
typedef void (kgdb_bus_error_hook_t)(void);

struct console;

#define _JBLEN 9
typedef int jmp_buf[_JBLEN];

#define breakpoint() __asm__ __volatile__("trapa   #0x3c")

#endif
