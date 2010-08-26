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
#ifndef _SYS_RESOURCE_H_
#define _SYS_RESOURCE_H_

#include <sys/cdefs.h>
#include <sys/types.h>     /* MUST be included before linux/resource.h */

/* TRICK AHEAD: <linux/resource.h> defines a getrusage function with
 *              a non-standard signature. this is surprising because the
 *              syscall seems to use the standard one instead.
 *              once again, creative macro usage saves the days
 */
#define  getrusage   __kernel_getrusage
#include <linux/resource.h>
#undef   getrusage

typedef unsigned long rlim_t;

__BEGIN_DECLS

extern int getpriority(int, int);
extern int setpriority(int, int, int);
extern int getrlimit(int resource, struct rlimit *rlp);
extern int setrlimit(int resource, const struct rlimit *rlp);
extern int getrusage(int  who, struct rusage*  r_usage);

__END_DECLS

#endif /* _SYS_RESOURCE_H_ */
