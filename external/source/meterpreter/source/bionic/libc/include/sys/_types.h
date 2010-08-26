/*	$OpenBSD: _types.h,v 1.1 2006/01/06 18:53:05 millert Exp $	*/

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)types.h	8.3 (Berkeley) 1/5/94
 */

#ifndef _SYS__TYPES_H_
#define	_SYS__TYPES_H_

#undef  __KERNEL_STRICT_NAMES
#define __KERNEL_STRICT_NAMES  1

#include <machine/_types.h>

typedef	unsigned long	__cpuid_t;	/* CPU id */
typedef	__int32_t	__dev_t;	/* device number */
typedef	__uint32_t	__fixpt_t;	/* fixed point number */
typedef	__uint32_t	__gid_t;	/* group id */
typedef	__uint32_t	__id_t;		/* may contain pid, uid or gid */
typedef __uint32_t	__in_addr_t;	/* base type for internet address */
typedef __uint16_t	__in_port_t;	/* IP port type */
typedef	__uint32_t	__ino_t;	/* inode number */
typedef	long		__key_t;	/* IPC key (for Sys V IPC) */
typedef	__uint32_t	__mode_t;	/* permissions */
typedef	__uint32_t	__nlink_t;	/* link count */
typedef	__int32_t	__pid_t;	/* process id */
typedef __uint64_t	__rlim_t;	/* resource limit */
typedef __uint16_t	__sa_family_t;	/* sockaddr address family type */
typedef	__int32_t	__segsz_t;	/* segment size */
typedef __uint32_t	__socklen_t;	/* length type for network syscalls */
typedef	__int32_t	__swblk_t;	/* swap offset */
typedef	__uint32_t	__uid_t;	/* user id */
typedef	__uint32_t	__useconds_t;	/* microseconds */
typedef	__int32_t	__suseconds_t;	/* microseconds (signed) */

/*
 * mbstate_t is an opaque object to keep conversion state, during multibyte
 * stream conversions. The content must not be referenced by user programs.
 */
typedef union {
	char __mbstate8[128];
	__int64_t __mbstateL;			/* for alignment */
} __mbstate_t;

/* BIONIC: if we're using non-cleaned up user-level kernel headers, 
 *         this will prevent many type declaration conflicts
 */
#define  __KERNEL_STRICT_NAMES  1

#endif /* !_SYS__TYPES_H_ */
