/*	$NetBSD: heap.h,v 1.1.1.1 2004/05/20 19:49:41 christos Exp $	*/

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

typedef int (*heap_higher_priority_func)(void *, void *);
typedef void (*heap_index_func)(void *, int);
typedef void (*heap_for_each_func)(void *, void *);

typedef struct heap_context {
	int array_size;
	int array_size_increment;
	int heap_size;
	void **heap;
	heap_higher_priority_func higher_priority;
	heap_index_func index;
} *heap_context;

#define heap_new	__heap_new
#define heap_free	__heap_free
#define heap_insert	__heap_insert
#define heap_delete	__heap_delete
#define heap_increased	__heap_increased
#define heap_decreased	__heap_decreased
#define heap_element	__heap_element
#define heap_for_each	__heap_for_each

heap_context	heap_new(heap_higher_priority_func, heap_index_func, int);
int		heap_free(heap_context);
int		heap_insert(heap_context, void *);
int		heap_delete(heap_context, int);
int		heap_increased(heap_context, int);
int		heap_decreased(heap_context, int);
void *		heap_element(heap_context, int);
int		heap_for_each(heap_context, heap_for_each_func, void *);
