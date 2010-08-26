/*	$NetBSD: nsdispatch.c,v 1.30 2005/11/29 03:11:59 christos Exp $	*/

/*-
 * Copyright (c) 1997, 1998, 1999, 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Luke Mewburn; and by Jason R. Thorpe.
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

/*-
 * Copyright (c) 2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * Portions of this software were developed for the FreeBSD Project by
 * Jacques A. Vidrine, Safeport Network Services, and Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <assert.h>
#ifdef __ELF__
#include <dlfcn.h>
#endif /* __ELF__ */
#include <fcntl.h>
#define _NS_PRIVATE
#include <nsswitch.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static nss_method
_nsmethod(const char *source, const char *database, const char *method,
    const ns_dtab disp_tab[], void **cb_data)
{
	int	curdisp;

	if (disp_tab != NULL) {
		for (curdisp = 0; disp_tab[curdisp].src != NULL; curdisp++) {
			if (strcasecmp(source, disp_tab[curdisp].src) == 0) {
				*cb_data = disp_tab[curdisp].cb_data;
				return (disp_tab[curdisp].callback);
			}
		}
	}

	*cb_data = NULL;
	return (NULL);
}

int
/*ARGSUSED*/
nsdispatch(void *retval, const ns_dtab disp_tab[], const char *database,
	    const char *method, const ns_src defaults[], ...)
{
	va_list		 ap;
	int		 i, result;
	const ns_src	*srclist;
	int		 srclistsize;
	nss_method	 cb;
	void		*cb_data;

	/* retval may be NULL */
	/* disp_tab may be NULL */
	assert(database != NULL);
	assert(method != NULL);
	assert(defaults != NULL);
	if (database == NULL || method == NULL || defaults == NULL)
		return (NS_UNAVAIL);

        srclist = defaults;
        srclistsize = 0;
        while (srclist[srclistsize].name != NULL)
                srclistsize++;

	result = 0;

	for (i = 0; i < srclistsize; i++) {
		cb = _nsmethod(srclist[i].name, database, method,
		    disp_tab, &cb_data);
		result = 0;
		if (cb != NULL) {
			va_start(ap, defaults);
			result = (*cb)(retval, cb_data, ap);
			va_end(ap);
			if (defaults[0].flags & NS_FORCEALL)
				continue;
			if (result & srclist[i].flags)
				break;
		}
	}
	result &= NS_STATUSMASK;	/* clear private flags in result */

	return (result ? result : NS_NOTFOUND);
}
