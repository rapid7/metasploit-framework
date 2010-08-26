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
#ifndef _ARCH_X86_CACHE_H
#define _ARCH_X86_CACHE_H

#define L1_CACHE_SHIFT (CONFIG_X86_L1_CACHE_SHIFT)
#define L1_CACHE_BYTES (1 << L1_CACHE_SHIFT)

#define __read_mostly __attribute__((__section__(".data.read_mostly")))

#endif
