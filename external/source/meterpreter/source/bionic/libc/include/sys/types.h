/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _SYS_TYPES_H_
#define _SYS_TYPES_H_

#define __need_size_t
#define __need_ptrdiff_t
#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include <linux/posix_types.h>
#include <asm/types.h>
#include <linux/types.h>
#include <machine/kernel.h>

typedef __u32    __kernel_dev_t;

/* be careful with __kernel_gid_t and __kernel_uid_t
 * these are defined as 16-bit for legacy reason, but
 * the kernel uses 32-bits instead.
 *
 * 32-bit valuea are required for Android, so use
 * __kernel_uid32_t and __kernel_gid32_t
 */

typedef __kernel_blkcnt_t    blkcnt_t;
typedef __kernel_blksize_t   blksize_t;
typedef __kernel_clock_t     clock_t;
typedef __kernel_clockid_t   clockid_t;
typedef __kernel_dev_t       dev_t;
typedef __kernel_fsblkcnt_t  fsblkcnt_t;
typedef __kernel_fsfilcnt_t  fsfilcnt_t;
typedef __kernel_gid32_t     gid_t;
typedef __kernel_id_t        id_t;
typedef __kernel_ino_t       ino_t;
typedef __kernel_key_t       key_t;
typedef __kernel_mode_t      mode_t;
typedef __kernel_nlink_t	 nlink_t;
#define _OFF_T_DEFINED_
typedef __kernel_off_t       off_t;
typedef __kernel_loff_t      loff_t;
typedef loff_t               off64_t;  /* GLibc-specific */

typedef __kernel_pid_t		 pid_t;

/* while POSIX wants these in <sys/types.h>, we
 * declare then in <pthread.h> instead */
#if 0
typedef  .... pthread_attr_t;
typedef  .... pthread_cond_t;
typedef  .... pthread_condattr_t;
typedef  .... pthread_key_t;
typedef  .... pthread_mutex_t;
typedef  .... pthread_once_t;
typedef  .... pthread_rwlock_t;
typedef  .... pthread_rwlock_attr_t;
typedef  .... pthread_t;
#endif

#ifndef _SIZE_T_DEFINED_
#define _SIZE_T_DEFINED_
typedef unsigned int  size_t;
#endif

/* size_t is defined by the GCC-specific <stddef.h> */
#ifndef _SSIZE_T_DEFINED_
#define _SSIZE_T_DEFINED_
typedef long int  ssize_t;
#endif

typedef __kernel_suseconds_t  suseconds_t;
typedef __kernel_time_t       time_t;
typedef __kernel_uid32_t        uid_t;
typedef signed long           useconds_t;

typedef __kernel_daddr_t	daddr_t;
typedef __kernel_timer_t	timer_t;
typedef __kernel_mqd_t		mqd_t;

typedef __kernel_caddr_t    caddr_t;
typedef unsigned int        uint_t;
typedef unsigned int        uint;

/* for some applications */
#include <sys/sysmacros.h>

#ifdef __BSD_VISIBLE
typedef	unsigned char	u_char;
typedef	unsigned short	u_short;
typedef	unsigned int	u_int;
typedef	unsigned long	u_long;

typedef uint32_t       u_int32_t;
typedef uint16_t       u_int16_t;
typedef uint8_t        u_int8_t;
typedef uint64_t       u_int64_t;
#endif

#endif
