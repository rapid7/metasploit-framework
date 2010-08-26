/*	$NetBSD: res_compat.c,v 1.1 2004/06/09 18:07:03 christos Exp $	*/

/*-
 * Copyright (c) 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: res_compat.c,v 1.1 2004/06/09 18:07:03 christos Exp $");
#endif

#include <sys/types.h>
#include <arpa/inet.h>
#include "arpa_nameser.h"
#include <netdb.h>
#include <string.h>
#define __OLD_RES_STATE
#ifdef ANDROID_CHANGES
#include "resolv_private.h"
#else
#include "resolv.h"
#endif

#undef _res

/*
 * Binary Compatibility; this symbol does not appear in a header file
 * Most userland programs use this to set res_options before res_init()
 * is called. There are hooks to res_init() to consult the data in this
 * structure. The hooks are provided indirectly by the two functions below.
 * We depend on the fact the the first 440 [32 bit machines] bytes are
 * shared between the two structures.
 */
#ifndef __BIND_NOSTATIC
struct __res_state _res
#if defined(__BIND_RES_TEXT)
	= { RES_TIMEOUT, }      /* Motorola, et al. */
# endif
;

void *__res_get_old_state(void);
void __res_put_old_state(void *);

void *
__res_get_old_state(void)
{
	return &_res;
}

void
__res_put_old_state(void *res)
{
	(void)memcpy(&_res, res, sizeof(_res));
}
#endif
