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

#ifndef _LINKER_H_
#define _LINKER_H_

#include <unistd.h>
#include <sys/types.h>
#include <linux/elf.h>

#undef PAGE_MASK
#undef PAGE_SIZE
#define PAGE_SIZE 4096
#define PAGE_MASK 4095

void debugger_init();
const char *addr_to_name(unsigned addr);

/* magic shared structures that GDB knows about */

struct link_map
{
    uintptr_t l_addr;
    char * l_name;
    uintptr_t l_ld;
    struct link_map * l_next;
    struct link_map * l_prev;
};

/* needed for dl_iterate_phdr to be passed to the callbacks provided */
struct dl_phdr_info
{
    Elf32_Addr dlpi_addr;
    const char *dlpi_name;
    const Elf32_Phdr *dlpi_phdr;
    Elf32_Half dlpi_phnum;
};


// Values for r_debug->state
enum {
    RT_CONSISTENT,
    RT_ADD,
    RT_DELETE
};

struct r_debug
{
    int32_t r_version;
    struct link_map * r_map;
    void (*r_brk)(void);
    int32_t r_state;
    uintptr_t r_ldbase;
};

typedef struct soinfo soinfo;

#define FLAG_LINKED     0x00000001
#define FLAG_ERROR      0x00000002
#define FLAG_EXE        0x00000004 // The main executable
#define FLAG_PRELINKED  0x00000008 // This is a pre-linked lib

#define SOINFO_NAME_LEN 128

struct soinfo
{
    const char name[SOINFO_NAME_LEN];
    Elf32_Phdr *phdr;
    int phnum;
    unsigned entry;
    unsigned base;
    unsigned size;
    // buddy-allocator index, negative for prelinked libraries
    int ba_index;

    unsigned *dynamic;

    unsigned wrprotect_start;
    unsigned wrprotect_end;

    soinfo *next;
    unsigned flags;

    const char *strtab;
    Elf32_Sym *symtab;

    unsigned nbucket;
    unsigned nchain;
    unsigned *bucket;
    unsigned *chain;

    unsigned *plt_got;

    Elf32_Rel *plt_rel;
    unsigned plt_rel_count;

    Elf32_Rel *rel;
    unsigned rel_count;

#ifdef ANDROID_SH_LINKER
    Elf32_Rela *plt_rela;
    unsigned plt_rela_count;

    Elf32_Rela *rela;
    unsigned rela_count;
#endif /* ANDROID_SH_LINKER */

    unsigned *preinit_array;
    unsigned preinit_array_count;

    unsigned *init_array;
    unsigned init_array_count;
    unsigned *fini_array;
    unsigned fini_array_count;

    void (*init_func)(void);
    void (*fini_func)(void);

#ifdef ANDROID_ARM_LINKER
    /* ARM EABI section used for stack unwinding. */
    unsigned *ARM_exidx;
    unsigned ARM_exidx_count;
#endif

    unsigned refcount;
    struct link_map linkmap;
};


extern soinfo libdl_info;

/* these must all be powers of two */
#ifdef ARCH_SH
#define LIBBASE 0x60000000
#define LIBLAST 0x70000000
#define LIBINC  0x00100000
#else
#define LIBBASE 0x80000000
#define LIBLAST 0x90000000
#define LIBINC  0x00100000
#endif

#ifdef ANDROID_ARM_LINKER

#define R_ARM_COPY       20
#define R_ARM_GLOB_DAT   21
#define R_ARM_JUMP_SLOT  22
#define R_ARM_RELATIVE   23

/* According to the AAPCS specification, we only
 * need the above relocations. However, in practice,
 * the following ones turn up from time to time.
 */
#define R_ARM_ABS32      2
#define R_ARM_REL32      3

#elif defined(ANDROID_X86_LINKER)

#define R_386_32         1
#define R_386_PC32       2
#define R_386_GLOB_DAT   6
#define R_386_JUMP_SLOT  7
#define R_386_RELATIVE   8

#elif defined(ANDROID_SH_LINKER)

#define R_SH_DIR32      1
#define R_SH_GLOB_DAT   163
#define R_SH_JUMP_SLOT  164
#define R_SH_RELATIVE   165

#endif /* ANDROID_*_LINKER */


#ifndef DT_INIT_ARRAY
#define DT_INIT_ARRAY      25
#endif

#ifndef DT_FINI_ARRAY
#define DT_FINI_ARRAY      26
#endif

#ifndef DT_INIT_ARRAYSZ
#define DT_INIT_ARRAYSZ    27
#endif

#ifndef DT_FINI_ARRAYSZ
#define DT_FINI_ARRAYSZ    28
#endif

#ifndef DT_PREINIT_ARRAY
#define DT_PREINIT_ARRAY   32
#endif

#ifndef DT_PREINIT_ARRAYSZ
#define DT_PREINIT_ARRAYSZ 33
#endif

soinfo *find_library(const char *name);
soinfo *find_library_buf(const char *name, void *buf, size_t size);
unsigned unload_library(soinfo *si);
Elf32_Sym *lookup_in_library(soinfo *si, const char *name);
Elf32_Sym *lookup(const char *name, soinfo **found, soinfo *start);
soinfo *find_containing_library(void *addr);
Elf32_Sym *find_containing_symbol(void *addr, soinfo *si);
const char *linker_get_error(void);

#ifdef ANDROID_ARM_LINKER 
typedef long unsigned int *_Unwind_Ptr;
_Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int *pcount);
#elif defined(ANDROID_X86_LINKER) || defined(ANDROID_SH_LINKER)
int dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *);
#endif

#endif
