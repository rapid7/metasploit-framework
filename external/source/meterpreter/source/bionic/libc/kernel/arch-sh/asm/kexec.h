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
#ifndef __ASM_SH_KEXEC_H
#define __ASM_SH_KEXEC_H

#include <asm/ptrace.h>
#include <asm/string.h>

#define KEXEC_SOURCE_MEMORY_LIMIT (-1UL)

#define KEXEC_DESTINATION_MEMORY_LIMIT (-1UL)

#define KEXEC_CONTROL_MEMORY_LIMIT TASK_SIZE

#define KEXEC_CONTROL_PAGE_SIZE 4096

#define KEXEC_ARCH KEXEC_ARCH_SH

#endif
