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
#ifndef __ASM_SH_BUG_H
#define __ASM_SH_BUG_H

#define TRAPA_BUG_OPCODE 0xc33e  

#define HAVE_ARCH_BUG
#define HAVE_ARCH_WARN_ON

#define _EMIT_BUG_ENTRY   "\t.pushsection __bug_table,\"a\"\n"   "2:\t.long 1b\n"   "\t.short %O3\n"   "\t.org 2b+%O4\n"   "\t.popsection\n"

#define BUG()  do {   __asm__ __volatile__ (   "1:\t.short %O0\n"   _EMIT_BUG_ENTRY   :   : "n" (TRAPA_BUG_OPCODE),   "i" (__FILE__),   "i" (__LINE__), "i" (0),   "i" (sizeof(struct bug_entry)));  } while (0)

#define __WARN()  do {   __asm__ __volatile__ (   "1:\t.short %O0\n"   _EMIT_BUG_ENTRY   :   : "n" (TRAPA_BUG_OPCODE),   "i" (__FILE__),   "i" (__LINE__),   "i" (BUGFLAG_WARNING),   "i" (sizeof(struct bug_entry)));  } while (0)

#define WARN_ON(x) ({   int __ret_warn_on = !!(x);   if (__builtin_constant_p(__ret_warn_on)) {   if (__ret_warn_on)   __WARN();   } else {   if (unlikely(__ret_warn_on))   __WARN();   }   unlikely(__ret_warn_on);  })

#include <asm-generic/bug.h>

#endif
