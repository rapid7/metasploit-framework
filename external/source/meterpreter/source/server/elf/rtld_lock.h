/*-
 * Copyright 2003 Alexander Kabaev.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: head/libexec/rtld-elf/rtld_lock.h 185558 2008-12-02 11:58:31Z kib $
 */

#ifndef _RTLD_LOCK_H_
#define	_RTLD_LOCK_H_

#define	RTLI_VERSION	0x01
#define	MAX_RTLD_LOCKS	8

struct RtldLockInfo
{
	unsigned int rtli_version;
	void *(*lock_create)(void);
	void  (*lock_destroy)(void *);
	void  (*rlock_acquire)(void *);
	void  (*wlock_acquire)(void *);
	void  (*lock_release)(void *);
	int   (*thread_set_flag)(int);
	int   (*thread_clr_flag)(int);
	void  (*at_fork)(void);
};

extern void _late_rtld_thread_init(struct RtldLockInfo *);
extern void _rtld_atfork_pre(int *);
extern void _rtld_atfork_post(int *);

#ifdef IN_RTLD

struct rtld_lock;
typedef struct rtld_lock *rtld_lock_t;

extern rtld_lock_t	late_rtld_bind_lock;
extern rtld_lock_t	late_rtld_libc_lock;
extern rtld_lock_t	late_rtld_phdr_lock;

int	rlock_acquire(rtld_lock_t);
int 	wlock_acquire(rtld_lock_t);
void	rlock_release(rtld_lock_t, int);
void	wlock_release(rtld_lock_t, int);

#endif	/* IN_RTLD */

#endif
