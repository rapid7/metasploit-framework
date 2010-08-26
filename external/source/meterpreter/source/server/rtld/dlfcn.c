/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sys/types.h>

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include "linker.h"
#include "linker_format.h"
#include "linker_debug.h"

#include <sys/mman.h>

#define DL_SUCCESS                    0
#define DL_ERR_CANNOT_LOAD_LIBRARY    1
#define DL_ERR_INVALID_LIBRARY_HANDLE 2
#define DL_ERR_BAD_SYMBOL_NAME        3
#define DL_ERR_SYMBOL_NOT_FOUND       4
#define DL_ERR_SYMBOL_NOT_GLOBAL      5

static char dl_err_buf[1024];
static const char *dl_err_str;

static const char *dl_errors[] = {
    [DL_ERR_CANNOT_LOAD_LIBRARY] = "Cannot load library",
    [DL_ERR_INVALID_LIBRARY_HANDLE] = "Invalid library handle",
    [DL_ERR_BAD_SYMBOL_NAME] = "Invalid symbol name",
    [DL_ERR_SYMBOL_NOT_FOUND] = "Symbol not found",
    [DL_ERR_SYMBOL_NOT_GLOBAL] = "Symbol is not global",
};

#define likely(expr)   __builtin_expect (expr, 1)
#define unlikely(expr) __builtin_expect (expr, 0)

// pks, no mutexes now
// static pthread_mutex_t dl_lock = PTHREAD_MUTEX_INITIALIZER;

static void set_dlerror(int err)
{
    format_buffer(dl_err_buf, sizeof(dl_err_buf), "%s: %s", dl_errors[err],
             linker_get_error());
    dl_err_str = (const char *)&dl_err_buf[0];
};

void *dlopen(const char *filename, int flag)
{
    soinfo *ret;

    // pthread_mutex_lock(&dl_lock);
    ret = find_library(filename);
    if (unlikely(ret == NULL)) {
        set_dlerror(DL_ERR_CANNOT_LOAD_LIBRARY);
    } else {
        ret->refcount++;
    }
    // pthread_mutex_unlock(&dl_lock);
    return ret;
}

const char *dlerror(void)
{
    const char *tmp = dl_err_str;
    dl_err_str = NULL;
    return (const char *)tmp;
}

void *dlsym(void *handle, const char *symbol)
{
    soinfo *found;
    Elf32_Sym *sym;
    unsigned bind;

    // pthread_mutex_lock(&dl_lock);

    if(unlikely(handle == 0)) { 
        set_dlerror(DL_ERR_INVALID_LIBRARY_HANDLE);
        goto err;
    }
    if(unlikely(symbol == 0)) {
        set_dlerror(DL_ERR_BAD_SYMBOL_NAME);
        goto err;
    }

    if(handle == RTLD_DEFAULT) {
        sym = lookup(symbol, &found, NULL);
    } else if(handle == RTLD_NEXT) {
        void *ret_addr = __builtin_return_address(0);
        soinfo *si = find_containing_library(ret_addr);

        sym = NULL;
        if(si && si->next) {
            sym = lookup(symbol, &found, si->next);
        }
    } else {
        found = (soinfo*)handle;
        sym = lookup_in_library(found, symbol);
    }

    if(likely(sym != 0)) {
        bind = ELF32_ST_BIND(sym->st_info);

        if(likely((bind == STB_GLOBAL) && (sym->st_shndx != 0))) {
            unsigned ret = sym->st_value + found->base;
            // pthread_mutex_unlock(&dl_lock);
            return (void*)ret;
        }

        set_dlerror(DL_ERR_SYMBOL_NOT_GLOBAL);
    }
    else
        set_dlerror(DL_ERR_SYMBOL_NOT_FOUND);

err:
    // pthread_mutex_unlock(&dl_lock);
    return 0;
}

int dladdr(void *addr, Dl_info *info)
{
    int ret = 0;

    // pthread_mutex_lock(&dl_lock);

    /* Determine if this address can be found in any library currently mapped */
    soinfo *si = find_containing_library(addr);

    if(si) {
        memset(info, 0, sizeof(Dl_info));

        info->dli_fname = si->name;
        info->dli_fbase = (void*)si->base;

        /* Determine if any symbol in the library contains the specified address */
        Elf32_Sym *sym = find_containing_symbol(addr, si);

        if(sym != NULL) {
            info->dli_sname = si->strtab + sym->st_name;
            info->dli_saddr = (void*)(si->base + sym->st_value);
        }

        ret = 1;
    }

    // pthread_mutex_unlock(&dl_lock);

    return ret;
}

int dlclose(void *handle)
{
    // pthread_mutex_lock(&dl_lock);
    (void)unload_library((soinfo*)handle);
    // pthread_mutex_unlock(&dl_lock);
    return 0;
}

#include "zlib.h"

// PKS, begin part of libloader.c :)

/*
 * Libraries we need to unpack for server startup
 *
 */
static int const gz_magic[2] = {0x1f, 0x8b}; /* gzip magic header */

/* gzip flag byte */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */


#define    EOF     (-1)
/* ===========================================================================
      Check the gzip header of a gz_stream opened for reading. Set the stream
    mode to transparent if the gzip magic header is not present; set s->err
    to Z_DATA_ERROR if the magic header is present but the rest of the header
    is incorrect.
    IN assertion: the stream s has already been created sucessfully;
       s->stream.avail_in is zero for the first time, but may be non-zero
       for concatenated .gz files.
*/
static int
check_header(unsigned char **input_buffer, int *input_length)
{
    int method; /* method byte */
    int flags;  /* flags byte */
    int c;
    int len = *input_length;
    unsigned char *inbuf = *input_buffer;

    if (len < 2) 
	    return Z_DATA_ERROR;

    if (inbuf[0] != gz_magic[0] ||
        inbuf[1] != gz_magic[1])
	    return Z_DATA_ERROR;

    len -= 2;
    inbuf += 2;

    /* Check the rest of the gzip header */
    method = inbuf[0];
    flags = inbuf[1];
    if (method != Z_DEFLATED || (flags & RESERVED) != 0)
	    return Z_DATA_ERROR;
    
    /* Discard time, xflags and OS code: */
    inbuf += 8;
    len -= 8;

    if ((flags & EXTRA_FIELD) != 0) { /* skip the extra field */
	    int field_len  =  (uInt)inbuf[0];
	    field_len += ((uInt)inbuf[1])<<8;
	    inbuf += 2;
	    len -= 2;
	    /* len is garbage if EOF but the loop below will quit anyway */
	    while (field_len-- != 0 && *(int *)inbuf != EOF) {
		    inbuf++;
		    len--;
	    }
    }
    /*
     * note that the original name skipping logics seems to be buggy
     *
     */
    if ((flags & ORIG_NAME) != 0) { /* skip the original file name */
	    while ((c = *inbuf) != 0 && c != EOF) {
		    inbuf++;
		    len--;
	    }
	    inbuf++;
	    len--;
    }
    if ((flags & COMMENT) != 0) {   /* skip the .gz file comment */
	    while ((c = *inbuf) != 0 && c != EOF) {
		    inbuf++;
		    len--;
	    }
    }
    if ((flags & HEAD_CRC) != 0) {  /* skip the header crc */
	    inbuf += 2;
	    len -= 2;
    }

    *input_length = len;
    *input_buffer = inbuf;
    return Z_OK;
}

#define TMPLIBSIZE (4 * 1024 * 1024)

// XXX replace with a single mmap, incrementing pointer, no free,
// and munmap (in dlopenbuf probably.

void *zalloc(void *opaque, unsigned int count, unsigned int size)
{
	unsigned int *ret;
	unsigned int tsz;

	tsz = ((count * size) + PAGE_SIZE) & ~PAGE_MASK;

	ret = mmap(0, tsz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if(ret == MAP_FAILED) return NULL;

	// TRACE("[ zalloc() allocated %08x bytes @ %08x\n", tsz, ret);
	ret[0] = tsz;
	return ++ret;
}

void zfree(void *opaque, void *addr)
{
	unsigned int *ret;

	ret = (unsigned int *)(addr);
	--ret;
	// TRACE("[ zfree() called. addr = %08x, ret = %08x, size = %08x ]\n", addr, ret, *ret);
	munmap(ret, ret[0]);
}

void *dlopenbuf(const char *name, void *data, size_t len)
{
	unsigned char *input_buffer, *output_buffer = NULL;;
	int input_size;
	z_stream stream;
	void *ret = NULL;
	int status;

	memset(&stream, 0, sizeof(z_stream));

	input_buffer = (unsigned char *)(data);
	input_size = len;

	output_buffer = mmap(0, TMPLIBSIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	
	if(check_header(&input_buffer, &input_size) != Z_OK) {
		TRACE("[ dlopenbuf(), we have an uncompressed file ]\n");
		goto uncompressed;
	}
	
	stream.zalloc = zalloc;
	stream.zfree = zfree;
	stream.avail_in = input_size;
	stream.next_in = input_buffer;
	stream.avail_out = TMPLIBSIZE;
	stream.next_out = output_buffer;
	inflateInit2(&stream, -MAX_WBITS);
	status = inflate(&stream, Z_FINISH);
	
	if(status != Z_STREAM_END) {
		TRACE("[ dlopenbuf(), failed to decompress. status: %d ]\n", status);
		goto out;
	}

	input_buffer = output_buffer;
	// TRACE("[ dlopenbuf(), decompressed. stream.avail_out = %d/%08x ]\n", stream.avail_out, stream.avail_out);
	input_size = TMPLIBSIZE - stream.avail_out;

uncompressed:
	ret = find_library_buf(name, input_buffer, input_size);	
out:
	if(output_buffer) {
		munmap(output_buffer, TMPLIBSIZE);
	}
	return ret;

}


#if defined(ANDROID_ARM_LINKER)
//                     0000000 00011111 111112 22222222 2333333 333344444444445555555
//                     0123456 78901234 567890 12345678 9012345 678901234567890123456
#define ANDROID_LIBDL_STRTAB \
                      "dlopen\0dlclose\0dlsym\0dlerror\0dladdr\0dl_unwind_find_exidx\0"

#elif defined(ANDROID_X86_LINKER)
//                     0000000 00011111 111112 22222222 2333333 3333444444444455
//                     0123456 78901234 567890 12345678 9012345 6789012345678901
#define ANDROID_LIBDL_STRTAB \
                      "dlopen\0dlclose\0dlsym\0dlerror\0dladdr\0dl_iterate_phdr\0dlopenbuf\0"

#elif defined(ANDROID_SH_LINKER)
//                     0000000 00011111 111112 22222222 2333333 3333444444444455
//                     0123456 78901234 567890 12345678 9012345 6789012345678901
#define ANDROID_LIBDL_STRTAB \
                      "dlopen\0dlclose\0dlsym\0dlerror\0dladdr\0dl_iterate_phdr\0"

#else /* !defined(ANDROID_ARM_LINKER) && !defined(ANDROID_X86_LINKER) */
#error Unsupported architecture. Only ARM and x86 are presently supported.
#endif


static Elf32_Sym libdl_symtab[] = {
      // total length of libdl_info.strtab, including trailing 0
      // This is actually the the STH_UNDEF entry. Technically, it's
      // supposed to have st_name == 0, but instead, it points to an index
      // in the strtab with a \0 to make iterating through the symtab easier.
    { st_name: sizeof(ANDROID_LIBDL_STRTAB) - 1,
    },
    { st_name: 0,   // starting index of the name in libdl_info.strtab
      st_value: (Elf32_Addr) &dlopen,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    },
    { st_name: 7,
      st_value: (Elf32_Addr) &dlclose,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    },
    { st_name: 15,
      st_value: (Elf32_Addr) &dlsym,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    },
    { st_name: 21,
      st_value: (Elf32_Addr) &dlerror,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    },
    { st_name: 29,
      st_value: (Elf32_Addr) &dladdr,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    },
#ifdef ANDROID_ARM_LINKER
    { st_name: 36,
      st_value: (Elf32_Addr) &dl_unwind_find_exidx,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    },
#elif defined(ANDROID_X86_LINKER)
    { st_name: 36,
      st_value: (Elf32_Addr) &dl_iterate_phdr,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    },
    { st_name: 52,
      st_value: (Elf32_Addr) &dlopenbuf,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    }, // once arm is supported, move this before optional symbols 
#elif defined(ANDROID_SH_LINKER)
    { st_name: 36,
      st_value: (Elf32_Addr) &dl_iterate_phdr,
      st_info: STB_GLOBAL << 4,
      st_shndx: 1,
    },
#endif

};

/* Fake out a hash table with a single bucket.
 * A search of the hash table will look through
 * libdl_symtab starting with index [1], then
 * use libdl_chains to find the next index to
 * look at.  libdl_chains should be set up to
 * walk through every element in libdl_symtab,
 * and then end with 0 (sentinel value).
 *
 * I.e., libdl_chains should look like
 * { 0, 2, 3, ... N, 0 } where N is the number
 * of actual symbols, or nelems(libdl_symtab)-1
 * (since the first element of libdl_symtab is not
 * a real symbol).
 *
 * (see _elf_lookup())
 *
 * Note that adding any new symbols here requires
 * stubbing them out in libdl.
 */
static unsigned libdl_buckets[1] = { 1 };
static unsigned libdl_chains[7] = { 0, 2, 3, 4, 5, 6, 7, 0 };

extern soinfo libcrap_info;

soinfo libdl_info = {
    name: "libdl.so",
    flags: FLAG_LINKED,

    strtab: ANDROID_LIBDL_STRTAB,
    symtab: libdl_symtab,

    nbucket: 1,
    nchain: 7,
    bucket: libdl_buckets,
    chain: libdl_chains,
};
    

