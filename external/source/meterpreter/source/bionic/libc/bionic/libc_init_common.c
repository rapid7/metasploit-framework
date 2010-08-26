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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <elf.h>
#include <asm/page.h>
#include "pthread_internal.h"
#include "atexit.h"
#include "libc_init_common.h"

#include <bionic_tls.h>
#include <errno.h>

extern unsigned __get_sp(void);
extern pid_t    gettid(void);

char*  __progname;
char **environ;

/* from asm/page.h */
unsigned int __page_size = PAGE_SIZE;
unsigned int __page_shift = PAGE_SHIFT;

static char *__default_environ[] = {
	"USER=metasploit", 
	"HOME=/",
	"USERNAME=metasploit",
	"HISTFILE=/dev/null",
	"HISTSIZE=0",
	"PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
	NULL
};


void __libc_init_common()
{
    pthread_attr_t             thread_attr;
    static pthread_internal_t  thread;
    static void*               tls_area[BIONIC_TLS_SLOTS];

    /* setup pthread runtime and main thread descriptor */
    unsigned stacktop = (__get_sp() & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
    unsigned stacksize = 128 * 1024;
    unsigned stackbottom = stacktop - stacksize;

    pthread_attr_init(&thread_attr);
    pthread_attr_setstack(&thread_attr, (void*)stackbottom, stacksize);
    _init_thread(&thread, gettid(), &thread_attr, (void*)stackbottom);
    __init_tls(tls_area, &thread);

    /* clear errno - requires TLS area */
    errno = 0;

    /* set program name */
    __progname = "metasploit";

    /* setup environment pointer */
    environ = __default_environ;

}
