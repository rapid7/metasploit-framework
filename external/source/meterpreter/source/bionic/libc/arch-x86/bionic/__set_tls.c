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
#include <pthread.h>


struct user_desc {
    unsigned int    entry_number;
    unsigned long   base_addr;
    unsigned int    limit;
    unsigned int    seg_32bit:1;
    unsigned int    contents:2;
    unsigned int    read_exec_only:1;
    unsigned int    limit_in_pages:1;
    unsigned int    seg_not_present:1;
    unsigned int    useable:1;
    unsigned int    empty:25;
};

extern int __set_thread_area(struct user_desc *u_info);

/* the following can't be const, since the first call will
 * update the 'entry_number' field
 */
static struct user_desc  _tls_desc =
{
    -1,
    0,
    0x1000,
    1,
    0,
    0,
    1,
    0,
    1,
    0
};

struct _thread_area_head {
    void *self;
};

/* we implement thread local storage through the gs: segment descriptor
 * we create a segment descriptor for the tls
 */
int __set_tls(void *ptr)
{
    int   rc, segment;

    _tls_desc.base_addr = (unsigned long)ptr;

    /* We also need to write the location of the tls to ptr[0] */
    ((struct _thread_area_head *)ptr)->self = ptr;

    rc = __set_thread_area( &_tls_desc );
    if (rc != 0)
    {
        /* could not set thread local area */
        return -1;
    }

    /* this weird computation comes from GLibc */
    segment = _tls_desc.entry_number*8 + 3;
    asm __volatile__ (
        "   movw %w0, %%gs" :: "q"(segment)
    );
    return 0;
}



