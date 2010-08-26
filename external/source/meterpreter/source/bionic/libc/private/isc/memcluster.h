/*	$NetBSD: memcluster.h,v 1.1.1.1 2004/05/20 19:49:41 christos Exp $	*/

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1997,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef MEMCLUSTER_H
#define MEMCLUSTER_H

#include <stdio.h>

#define meminit		__meminit
#ifdef MEMCLUSTER_DEBUG
#define memget(s)	__memget_debug(s, __FILE__, __LINE__)
#define memput(p, s)	__memput_debug(p, s, __FILE__, __LINE__)
#else /*MEMCLUSTER_DEBUG*/
#ifdef MEMCLUSTER_RECORD
#define memget(s)	__memget_record(s, __FILE__, __LINE__)
#define memput(p, s)	__memput_record(p, s, __FILE__, __LINE__)
#else /*MEMCLUSTER_RECORD*/
#define memget		__memget
#define memput		__memput
#endif /*MEMCLUSTER_RECORD*/
#endif /*MEMCLUSTER_DEBUG*/
#define memstats	__memstats
#define memactive	__memactive

int	meminit(size_t, size_t);
void *	__memget(size_t);
void 	__memput(void *, size_t);
void *	__memget_debug(size_t, const char *, int);
void 	__memput_debug(void *, size_t, const char *, int);
void *	__memget_record(size_t, const char *, int);
void 	__memput_record(void *, size_t, const char *, int);
void 	memstats(FILE *);
int	memactive(void);

#endif /* MEMCLUSTER_H */
