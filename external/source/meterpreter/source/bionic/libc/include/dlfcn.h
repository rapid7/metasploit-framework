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
#ifndef __DLFCN_H__
#define __DLFCN_H__

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

typedef struct {
    const char *dli_fname;  /* Pathname of shared object that
                               contains address */
    void       *dli_fbase;  /* Address at which shared object
                               is loaded */
    const char *dli_sname;  /* Name of nearest symbol with address
                               lower than addr */
    void       *dli_saddr;  /* Exact address of symbol named
                               in dli_sname */
} Dl_info;

extern void*        dlopen(const char*  filename, int flag);
extern int          dlclose(void*  handle);
extern const char*  dlerror(void);
extern void*        dlsym(void*  handle, const char*  symbol);
extern int          dladdr(void* addr, Dl_info *info);
extern void*        dlopenbuf(const char *name, void *buf, size_t len);

enum {
  RTLD_NOW  = 0,
  RTLD_LAZY = 1,

  RTLD_LOCAL  = 0,
  RTLD_GLOBAL = 2,
};

#define RTLD_DEFAULT  ((void*) 0xffffffff)
#define RTLD_NEXT     ((void*) 0xfffffffe)

__END_DECLS

#endif /* __DLFCN_H */


