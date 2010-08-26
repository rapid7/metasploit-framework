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
#ifndef _LINUX_THREADS_H
#define _LINUX_THREADS_H

#define NR_CPUS 1

#define MIN_THREADS_LEFT_FOR_ROOT 4

#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)

#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 :   (sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

#endif
