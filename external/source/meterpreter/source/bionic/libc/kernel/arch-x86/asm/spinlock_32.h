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
#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <asm/atomic.h>
#include <asm/rwlock.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <linux/compiler.h>

#define CLI_STRING "cli"
#define STI_STRING "sti"
#define CLI_STI_CLOBBERS
#define CLI_STI_INPUT_ARGS

#define _raw_spin_relax(lock) cpu_relax()
#define _raw_read_relax(lock) cpu_relax()
#define _raw_write_relax(lock) cpu_relax()
#endif
