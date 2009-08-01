/*-
 * Copyright 2009 Metasploit Project
 *
 *
 * Copyright 1996, 1997, 1998, 1999, 2000 John D. Polstra.
 * Copyright 2003 Alexander Kabaev <kan@FreeBSD.ORG>.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: head/libexec/rtld-elf/rtld.c 194705 2009-06-23 14:12:49Z ed $
 */

/*
 * Dynamic linker for ELF.
 *
 * John Polstra <jdp@polstra.com>.
 */

#include <sys/mman.h>
#include <sys/errno.h>
#include <stdlib.h>
#include "dlfcn.h"

#include "debug.h"
#include "rtld.h"
#include "libmap.h"
#include "rtld_tls.h"

/*
 * Forget about sparc / alpha / ia64 for now 
 */ 
#define	PAGE_SIZE	4096
#define PAGE_MASK	(PAGE_SIZE-1)
#define round_page(x)           (((x) + PAGE_MASK) & ~PAGE_MASK)
#define trunc_page(x) ((unsigned long )(x) & ~(PAGE_MASK))
#define utrace(a, b)

#define PATH_MAX	1024
#define MAXPATHLEN	1024
#ifndef COMPAT_32BIT
#define PATH_RTLD	"P0WNED"
#else
#define PATH_RTLD	"POWNED-32bit"
#endif

/*
 * Globals to control TLS allocation.
 */
size_t tls_last_offset;		/* Static TLS offset of last module */
size_t tls_last_size;		/* Static TLS size of last module */
size_t tls_static_space;	/* Static TLS space allocated */
int tls_dtv_generation = 1;	/* Used to detect when dtv size changes  */
int tls_max_index = 1;
int debug = 1;

/* Types. */
typedef void (*func_ptr_type)();
typedef void * (*path_enum_proc) (const char *path, size_t len, void *arg);

/*
 * This structure provides a reentrant way to keep a list of objects and
 * check which ones have already been processed in some way.
 */
typedef struct Struct_DoneList {
    const Obj_Entry **objs;		/* Array of object pointers */
    unsigned int num_alloc;		/* Allocated size of the array */
    unsigned int num_used;		/* Number of array slots used */
} DoneList;

/*
 * Data declarations.
 */
static char *error_message;	/* Message for dlerror(), or NULL */
struct r_debug r_debug;		/* for GDB; */
static bool libmap_disable;	/* Disable libmap */
static char *libmap_override;	/* Maps to use in addition to libmap.conf */
static bool trust;		/* False for setuid and setgid programs */
static bool dangerous_ld_env;	/* True if environment variables have been
				   used to affect the libraries loaded */
static char *ld_bind_now;	/* Environment variable for immediate binding */
static char *ld_debug;		/* Environment variable for debugging */
static char *ld_library_path;	/* Environment variable for search path */
static char *ld_preload;	/* Environment variable for libraries to
				   load first */
static char *ld_tracing;	/* Called from ldd to print libs */
static char *ld_utrace;		/* Use utrace() to log events. */
static Obj_Entry *obj_list;	/* Head of linked list of shared objects */
static Obj_Entry **obj_tail;	/* Link field of last object in list */
static Obj_Entry *obj_main;	/* The main program shared object */
static Obj_Entry obj_rtld;	/* The dynamic linker shared object */
static unsigned int obj_count;	/* Number of objects in obj_list */
static unsigned int obj_loads;	/* Number of objects in obj_list */

static Objlist list_global =	/* Objects dlopened with RTLD_GLOBAL */
  STAILQ_HEAD_INITIALIZER(list_global);
static Objlist list_main =	/* Objects loaded at program startup */
  STAILQ_HEAD_INITIALIZER(list_main);
static Objlist list_fini =	/* Objects needing fini() calls */
  STAILQ_HEAD_INITIALIZER(list_fini);

static Elf_Sym sym_zero;	/* For resolving undefined weak refs. */

#define GDB_STATE(s,m)	r_debug.r_state = s; r_debug_state(&r_debug,m);

extern Elf_Dyn _DYNAMIC;
#pragma weak _DYNAMIC
#ifndef RTLD_IS_DYNAMIC
#if 0
/* this is showing up as a valid symbol when it should not be */
#define	RTLD_IS_DYNAMIC()	(&_DYNAMIC != NULL)
#endif
#define	RTLD_IS_DYNAMIC()	(0)
#endif
#pragma weak dlopen
#pragma weak dlsym

#ifdef __linux__
void
_rtld_error(const char * x, ...) 
{
}
#endif

static func_ptr_type exports[] = {
#ifndef __linux__
    (func_ptr_type) &_rtld_error,
#endif
    (func_ptr_type) &dlclose,
    (func_ptr_type) &dlerror,
    (func_ptr_type) &dlopen,
    (func_ptr_type) &dlopenbuf,
    (func_ptr_type) &dlsym,
    NULL
};

/*
 * Global declarations normally provided by crt1.  The dynamic linker is
 * not built with crt1, so we have to provide them ourselves.
 */
char *__late_progname;
char **environ;

static void initlist_add_objects(Obj_Entry *obj, Obj_Entry **tail, Objlist *list);



/*
 * XXX temporary XXX
 *
 */
void exit(int);
#define abort()		exit(1)

/*
 * Fill in a DoneList with an allocation large enough to hold all of
 * the currently-loaded objects.  Keep this as a macro since it calls
 * alloca and we want that to occur within the scope of the caller.
 */
#define donelist_init(dlp)					\
    ((dlp)->objs = alloca(obj_count * sizeof (dlp)->objs[0]),	\
    assert((dlp)->objs != NULL),				\
    (dlp)->num_alloc = obj_count,				\
    (dlp)->num_used = 0)

#define	UTRACE_DLOPEN_START		1
#define	UTRACE_DLOPEN_STOP		2
#define	UTRACE_DLCLOSE_START		3
#define	UTRACE_DLCLOSE_STOP		4
#define	UTRACE_LOAD_OBJECT		5
#define	UTRACE_UNLOAD_OBJECT		6
#define	UTRACE_ADD_RUNDEP		7
#define	UTRACE_PRELOAD_FINISHED		8
#define	UTRACE_INIT_CALL		9
#define	UTRACE_FINI_CALL		10

struct utrace_rtld {
	char sig[4];			/* 'RTLD' */
	int event;
	void *handle;
	void *mapbase;			/* Used for 'parent' and 'init/fini' */
	size_t mapsize;
	int refcnt;			/* Used for 'mode' */
	char name[MAXPATHLEN];
};

#define	LD_UTRACE(e, h, mb, ms, r, n) do {			\
	if (ld_utrace != NULL)					\
		ld_utrace_log(e, h, mb, ms, r, n);		\
} while (0)

static void
ld_utrace_log(int event, void *handle, void *mapbase, size_t mapsize,
    int refcnt, const char *name)
{
	struct utrace_rtld ut;

	ut.sig[0] = 'R';
	ut.sig[1] = 'T';
	ut.sig[2] = 'L';
	ut.sig[3] = 'D';
	ut.event = event;
	ut.handle = handle;
	ut.mapbase = mapbase;
	ut.mapsize = mapsize;
	ut.refcnt = refcnt;
	bzero(ut.name, sizeof(ut.name));
	if (name)
		strlcpy(ut.name, name, sizeof(ut.name));
	utrace(&ut, sizeof(ut));
}

static int
object_match_name(const Obj_Entry *obj, const char *name)
{
    Name_Entry *entry;

    STAILQ_FOREACH(entry, &obj->names, link) {
	if (strcmp(name, entry->name) == 0)
	    return (1);
    }
    return (0);
}

/*
 * If the given object is already in the donelist, return true.  Otherwise
 * add the object to the list and return false.
 */
static bool
donelist_check(DoneList *dlp, const Obj_Entry *obj)
{
    unsigned int i;

    for (i = 0;  i < dlp->num_used;  i++)
	if (dlp->objs[i] == obj)
	    return true;
    /*
     * Our donelist allocation should always be sufficient.  But if
     * our threads locking isn't working properly, more shared objects
     * could have been loaded since we allocated the list.  That should
     * never happen, but we'll handle it properly just in case it does.
     */
    if (dlp->num_used < dlp->num_alloc)
	dlp->objs[dlp->num_used++] = obj;
    return false;
}

const char *
dlerror(void)
{
    char *msg = error_message;
    error_message = NULL;
    return msg;
}

static void
die(void)
{
    const char *msg = dlerror();

    if (msg == NULL)
	msg = "Fatal error";
    errx(1, "%s", msg);
    abort();
}

#if defined(__i386__) || defined(__amd64__) || defined(__sparc64__) || \
    defined(__arm__) || defined(__mips__)

/*
 * Allocate Static TLS using the Variant II method.
 */
void *
allocate_tls(Obj_Entry *objs, void *oldtls, size_t tcbsize, size_t tcbalign)
{
    Obj_Entry *obj;
    size_t size;
    char *tls;
    Elf_Addr *dtv, *olddtv;
    Elf_Addr segbase, oldsegbase, addr;
    int i;

    size = round(tls_static_space, tcbalign);

    assert(tcbsize >= 2*sizeof(Elf_Addr));
    tls = calloc(1, size + tcbsize);
    dtv = calloc(1, (tls_max_index + 2) * sizeof(Elf_Addr));

    segbase = (Elf_Addr)(tls + size);
    ((Elf_Addr*)segbase)[0] = segbase;
    ((Elf_Addr*)segbase)[1] = (Elf_Addr) dtv;

    dtv[0] = tls_dtv_generation;
    dtv[1] = tls_max_index;

    if (oldtls) {
	/*
	 * Copy the static TLS block over whole.
	 */
	oldsegbase = (Elf_Addr) oldtls;
	memcpy((void *)(segbase - tls_static_space),
	       (const void *)(oldsegbase - tls_static_space),
	       tls_static_space);

	/*
	 * If any dynamic TLS blocks have been created tls_get_addr(),
	 * move them over.
	 */
	olddtv = ((Elf_Addr**)oldsegbase)[1];
	for (i = 0; i < olddtv[1]; i++) {
	    if (olddtv[i+2] < oldsegbase - size || olddtv[i+2] > oldsegbase) {
		dtv[i+2] = olddtv[i+2];
		olddtv[i+2] = 0;
	    }
	}

	/*
	 * We assume that this block was the one we created with
	 * allocate_initial_tls().
	 */
	free_tls(oldtls, 2*sizeof(Elf_Addr), sizeof(Elf_Addr));
    } else {
	for (obj = objs; obj; obj = obj->next) {
	    if (obj->tlsoffset) {
		addr = segbase - obj->tlsoffset;
		memset((void*) (addr + obj->tlsinitsize),
		       0, obj->tlssize - obj->tlsinitsize);
		if (obj->tlsinit)
		    memcpy((void*) addr, obj->tlsinit, obj->tlsinitsize);
		dtv[obj->tlsindex + 1] = addr;
	    }
	}
    }

    return (void*) segbase;
}

void
free_tls(void *tls, size_t tcbsize, size_t tcbalign)
{
    size_t size;
    Elf_Addr* dtv;
    int dtvsize, i;
    Elf_Addr tlsstart, tlsend;

    /*
     * Figure out the size of the initial TLS block so that we can
     * find stuff which ___tls_get_addr() allocated dynamically.
     */
    size = round(tls_static_space, tcbalign);

    dtv = ((Elf_Addr**)tls)[1];
    dtvsize = dtv[1];
    tlsend = (Elf_Addr) tls;
    tlsstart = tlsend - size;
    for (i = 0; i < dtvsize; i++) {
	if (dtv[i+2] && (dtv[i+2] < tlsstart || dtv[i+2] > tlsend)) {
	    free((void*) dtv[i+2]);
	}
    }

    free((void*) tlsstart);
    free((void*) dtv);
}

#endif

bool
allocate_tls_offset(Obj_Entry *obj)
{
    size_t off;

    if (obj->tls_done)
	return true;

    if (obj->tlssize == 0) {
	obj->tls_done = true;
	return true;
    }

    if (obj->tlsindex == 1)
	off = calculate_first_tls_offset(obj->tlssize, obj->tlsalign);
    else
	off = calculate_tls_offset(tls_last_offset, tls_last_size,
				   obj->tlssize, obj->tlsalign);

    /*
     * If we have already fixed the size of the static TLS block, we
     * must stay within that size. When allocating the static TLS, we
     * leave a small amount of space spare to be used for dynamically
     * loading modules which use static TLS.
     */
    if (tls_static_space) {
	if (calculate_tls_end(off, obj->tlssize) > tls_static_space)
	    return false;
    }

    tls_last_offset = obj->tlsoffset = off;
    tls_last_size = obj->tlssize;
    obj->tls_done = true;

    return true;
}

void
free_tls_offset(Obj_Entry *obj)
{
#if defined(__i386__) || defined(__amd64__) || defined(__sparc64__) || \
    defined(__arm__) || defined(__mips__)
    /*
     * If we were the last thing to allocate out of the static TLS
     * block, we give our space back to the 'allocator'. This is a
     * simplistic workaround to allow libGL.so.1 to be loaded and
     * unloaded multiple times. We only handle the Variant II
     * mechanism for now - this really needs a proper allocator.
     */
    if (calculate_tls_end(obj->tlsoffset, obj->tlssize)
	== calculate_tls_end(tls_last_offset, tls_last_size)) {
	tls_last_offset -= obj->tlssize;
	tls_last_size = 0;
    }
#endif
}

/*
 * Common code for MD __tls_get_addr().
 */
void *
tls_get_addr_common(Elf_Addr** dtvp, int index, size_t offset)
{
    Elf_Addr* dtv = *dtvp;
    int lockstate;

    /* Check dtv generation in case new modules have arrived */
    if (dtv[0] != tls_dtv_generation) {
	Elf_Addr* newdtv;
	int to_copy;

	lockstate = wlock_acquire(late_rtld_bind_lock);
	newdtv = calloc(1, (tls_max_index + 2) * sizeof(Elf_Addr));
	to_copy = dtv[1];
	if (to_copy > tls_max_index)
	    to_copy = tls_max_index;
	memcpy(&newdtv[2], &dtv[2], to_copy * sizeof(Elf_Addr));
	newdtv[0] = tls_dtv_generation;
	newdtv[1] = tls_max_index;
	free(dtv);
	wlock_release(late_rtld_bind_lock, lockstate);
	*dtvp = newdtv;
    }

    /* Dynamically allocate module TLS if necessary */
    if (!dtv[index + 1]) {
	/* Signal safe, wlock will block out signals. */
	lockstate = wlock_acquire(late_rtld_bind_lock);
	if (!dtv[index + 1])
	    dtv[index + 1] = (Elf_Addr)allocate_module_tls(index);
	wlock_release(late_rtld_bind_lock, lockstate);
    }
    return (void*) (dtv[index + 1] + offset);
}

/*
 * Allocate TLS block for module with given index.
 */
void *
allocate_module_tls(int index)
{
    Obj_Entry* obj;
    char* p;

    for (obj = obj_list; obj; obj = obj->next) {
	if (obj->tlsindex == index)
	    break;
    }
    if (!obj) {
	_rtld_error("Can't find module with TLS index %d", index);
	die();
    }

    p = malloc(obj->tlssize);
    memcpy(p, obj->tlsinit, obj->tlsinitsize);
    memset(p + obj->tlsinitsize, 0, obj->tlssize - obj->tlsinitsize);

    return p;
}

const Ver_Entry *
fetch_ventry(const Obj_Entry *obj, unsigned long symnum)
{
    Elf_Versym vernum;

    if (obj->vertab) {
	vernum = VER_NDX(obj->versyms[symnum]);
	if (vernum >= obj->vernum) {
	    _rtld_error("%s: symbol %s has wrong verneed value %d",
		obj->path, obj->strtab + symnum, vernum);
	} else if (obj->vertab[vernum].hash != 0) {
	    return &obj->vertab[vernum];
	}
    }
    return NULL;
}
#ifndef FPTR_TARGET
#define FPTR_TARGET(f)	((Elf_Addr) (f))
#endif

static bool
is_exported(const Elf_Sym *def)
{
    Elf_Addr value;
    const func_ptr_type *p;

    value = (Elf_Addr)(obj_rtld.relocbase + def->st_value);
    for (p = exports;  *p != NULL;  p++)
	if (FPTR_TARGET(*p) == value)
	    return true;
    return false;
}

const Elf_Sym *
validate_sym(const char *name, unsigned long symnum, const Obj_Entry *obj,
    const Ver_Entry *ventry, int flags)
{
	const Elf_Sym *vsymp, *symp;
	const char *strp;
	Elf_Versym verndx;
	int vcount;
	vcount = 0;

	vsymp = NULL;
	symp = obj->symtab + symnum;
	strp = obj->strtab + symp->st_name;

	switch (ELF_ST_TYPE(symp->st_info)) {
	case STT_FUNC:
	case STT_NOTYPE:
	case STT_OBJECT:
	    if (symp->st_value == 0)
		return (NULL);
		/* fallthrough */
	case STT_TLS:
	    if (symp->st_shndx != SHN_UNDEF)
		break;
#ifndef __mips__
	    else if (((flags & SYMLOOK_IN_PLT) == 0) &&
		 (ELF_ST_TYPE(symp->st_info) == STT_FUNC))
		break;
		/* fallthrough */
#endif
	default:
	    return (NULL);
	}
	if (name[0] != strp[0] || strcmp(name, strp) != 0)
	    return (NULL);

	if (ventry == NULL) {
	    if (obj->versyms != NULL) {
		verndx = VER_NDX(obj->versyms[symnum]);
#ifdef ENABLE_SYM_VERSIONING
		/*
		 * We need to ignore symbol versions so we can link with
		 * our own version of libc
		 */
		if (verndx > obj->vernum) {
		    _rtld_error("%s: symbol %s references wrong version %d",
			obj->path, obj->strtab + symnum, verndx);
		    return (NULL);
		}
#endif
		/*
		 * If we are not called from dlsym (i.e. this is a normal
		 * relocation from unversioned binary, accept the symbol
		 * immediately if it happens to have first version after
		 * this shared object became versioned. Otherwise, if
		 * symbol is versioned and not hidden, remember it. If it
		 * is the only symbol with this name exported by the
		 * shared object, it will be returned as a match at the
		 * end of the function. If symbol is global (verndx < 2)
		 * accept it unconditionally.
		 */
		if ((flags & SYMLOOK_DLSYM) == 0 && verndx == VER_NDX_GIVEN)
		    return symp;
	        else if (verndx >= VER_NDX_GIVEN) {
		    if ((obj->versyms[symnum] & VER_NDX_HIDDEN) == 0) {
			if (vsymp == NULL)
			    vsymp = symp;
			vcount ++;
		    }
		    return (NULL);
		}
	    }
	    return symp;
	} else {
	    if (obj->versyms == NULL) {
		if (object_match_name(obj, ventry->name)) {
		    _rtld_error("%s: object %s should provide version %s for "
			"symbol %s", obj_rtld.path, obj->path, ventry->name,
			obj->strtab + symnum);
		    return (NULL);
		}
	    } else {
		verndx = VER_NDX(obj->versyms[symnum]);
		if (verndx > obj->vernum) {
		    _rtld_error("%s: symbol %s references wrong version %d",
			obj->path, obj->strtab + symnum, verndx);
		    return (NULL);
		}
		if (obj->vertab[verndx].hash != ventry->hash ||
		    strcmp(obj->vertab[verndx].name, ventry->name)) {
		    /*
		     * Version does not match. Look if this is a global symbol
		     * and if it is not hidden. If global symbol (verndx < 2)
		     * is available, use it. Do not return symbol if we are
		     * called by dlvsym, because dlvsym looks for a specific
		     * version and default one is not what dlvsym wants.
		     */
		    if ((flags & SYMLOOK_DLSYM) ||
			(obj->versyms[symnum] & VER_NDX_HIDDEN) ||
			(verndx >= VER_NDX_GIVEN))
			return (NULL);
		}
	    }

	    return symp;
	}	
}

static uint32_t
gnu_sym_hash (const char *s)
{
	uint32_t h = 5381;
	unsigned char c;

	for (c = *s; c != '\0'; c = *++s)
		h = h * 33 + c;
	return (h & 0xffffffff);
}

const Elf_Sym *
symlook_obj_gnu(const char *name, const Obj_Entry *obj, int flags)
{
	const Elf_Sym *symp;
	unsigned long symnum;
	Elf32_Word bucket;
	const Elf_Addr *bitmask;
	const Elf32_Word *hasharr;
	Elf_Addr bitmask_word;
	unsigned int hashbit1, hashbit2;
	uint32_t gnu_hash = gnu_sym_hash(name);

	bitmask = obj->gnu_bitmask;
	if (bitmask == NULL)
		return (NULL);

	bitmask_word = bitmask[(gnu_hash / __ELF_WORD_SIZE) &
	   obj->gnu_bitmask_idxbits];
	hashbit1 = gnu_hash & (__ELF_WORD_SIZE -1);
	hashbit2 = ((gnu_hash >> obj->gnu_shift)
	    & (__ELF_WORD_SIZE -1));
	if ((bitmask_word >> hashbit1) &
	    (bitmask_word >> hashbit2) & 1) {
		bucket = gnu_hash % obj->nbuckets;
		bucket = obj->gnu_buckets[bucket];
		if (bucket != 0) {
			hasharr = &obj->gnu_chain_zero[bucket];
			do {		
				if (((*hasharr ^ gnu_hash) >> 1) == 0) {
					symnum = hasharr - obj->gnu_chain_zero;
					if ((symp = validate_sym(name, symnum, obj, NULL, flags)) != NULL)
						return (symp);
				}
			} while ((*hasharr++ & 1u) == 0);
		}
	}
	return (NULL);
}

/*
 * Search the symbol table of a single shared object for a symbol of
 * the given name and version, if requested.  Returns a pointer to the
 * symbol, or NULL if no definition was found.
 *
 * The symbol's hash value is passed in for efficiency reasons; that
 * eliminates many recomputations of the hash value.
 */
const Elf_Sym *
symlook_obj(const char *name, unsigned long hash, const Obj_Entry *obj,
    const Ver_Entry *ventry, int flags)
{
    unsigned long symnum;
    const Elf_Sym *symp;
    symnum;

    if ((symp = symlook_obj_gnu(name, obj, flags)) != NULL)
	    return (symp);

    if (obj->buckets == NULL)
	return NULL;

    symnum = obj->buckets[hash % obj->nbuckets];

    
    for (; symnum != STN_UNDEF; symnum = obj->chains[symnum]) {

	    if (symnum >= obj->nchains)
		    return NULL;	/* Bad object */

	    if ((symp = validate_sym(name, symnum, obj, NULL, flags)) != NULL)
		    return (symp);
    }
#ifdef notyet
    return (vcount == 1) ? vsymp : NULL;
#endif
    return (NULL);
}

/*
 * Hash function for symbol table lookup.  Don't even think about changing
 * this.  It is specified by the System V ABI.
 */
unsigned long
elf_hash(const char *name)
{
    const unsigned char *p = (const unsigned char *) name;
    unsigned long h = 0;
    unsigned long g;

    while (*p != '\0') {
	h = (h << 4) + *p++;
	if ((g = h & 0xf0000000) != 0)
	    h ^= g >> 24;
	h &= ~g;
    }
    return h;
}

static const Elf_Sym *
symlook_list(const char *name, unsigned long hash, const Objlist *objlist,
  const Obj_Entry **defobj_out, const Ver_Entry *ventry, int flags,
  DoneList *dlp)
{
    const Elf_Sym *symp;
    const Elf_Sym *def;
    const Obj_Entry *defobj;
    const Objlist_Entry *elm;

    def = NULL;
    defobj = NULL;
    STAILQ_FOREACH(elm, objlist, link) {
	if (donelist_check(dlp, elm->obj))
	    continue;
	if ((symp = symlook_obj(name, hash, elm->obj, ventry, flags)) != NULL) {
	    if (def == NULL || ELF_ST_BIND(symp->st_info) != STB_WEAK) {
		def = symp;
		defobj = elm->obj;
		if (ELF_ST_BIND(def->st_info) != STB_WEAK)
		    break;
	    }
	}
    }
    if (def != NULL)
	*defobj_out = defobj;
    return def;
}

/*
 * Given a symbol name in a referencing object, find the corresponding
 * definition of the symbol.  Returns a pointer to the symbol, or NULL if
 * no definition was found.  Returns a pointer to the Obj_Entry of the
 * defining object via the reference parameter DEFOBJ_OUT.
 */
static const Elf_Sym *
symlook_default(const char *name, unsigned long hash, const Obj_Entry *refobj,
    const Obj_Entry **defobj_out, const Ver_Entry *ventry, int flags)
{
    DoneList donelist;
    const Elf_Sym *def;
    const Elf_Sym *symp;
    const Obj_Entry *obj;
    const Obj_Entry *defobj;
    const Objlist_Entry *elm;
    def = NULL;
    defobj = NULL;
    donelist_init(&donelist);

    /* Look first in the referencing object if linked symbolically. */
    if (refobj->symbolic && !donelist_check(&donelist, refobj)) {
	symp = symlook_obj(name, hash, refobj, ventry, flags);
	if (symp != NULL) {
	    def = symp;
	    defobj = refobj;
	}
    }

    /* Search all objects loaded at program start up. */
    if (def == NULL || ELF_ST_BIND(def->st_info) == STB_WEAK) {
	symp = symlook_list(name, hash, &list_main, &obj, ventry, flags,
	    &donelist);
	if (symp != NULL &&
	  (def == NULL || ELF_ST_BIND(symp->st_info) != STB_WEAK)) {
	    def = symp;
	    defobj = obj;
	}
    }

    /* Search all DAGs whose roots are RTLD_GLOBAL objects. */
    STAILQ_FOREACH(elm, &list_global, link) {
       if (def != NULL && ELF_ST_BIND(def->st_info) != STB_WEAK)
           break;
       symp = symlook_list(name, hash, &elm->obj->dagmembers, &obj, ventry,
	   flags, &donelist);
	if (symp != NULL &&
	  (def == NULL || ELF_ST_BIND(symp->st_info) != STB_WEAK)) {
	    def = symp;
	    defobj = obj;
	}
    }

    /* Search all dlopened DAGs containing the referencing object. */
    STAILQ_FOREACH(elm, &refobj->dldags, link) {
	if (def != NULL && ELF_ST_BIND(def->st_info) != STB_WEAK)
	    break;
	symp = symlook_list(name, hash, &elm->obj->dagmembers, &obj, ventry,
	    flags, &donelist);
	if (symp != NULL &&
	  (def == NULL || ELF_ST_BIND(symp->st_info) != STB_WEAK)) {
	    def = symp;
	    defobj = obj;
	}
    }

    /*
     * Search the dynamic linker itself, and possibly resolve the
     * symbol from there.  This is how the application links to
     * dynamic linker services such as dlopen.  Only the values listed
     * in the "exports" array can be resolved from the dynamic linker.
     */
    if (def == NULL || ELF_ST_BIND(def->st_info) == STB_WEAK) {
	symp = symlook_obj(name, hash, &obj_rtld, ventry, flags);
	if (symp != NULL)
		if (is_exported(symp)) {
			def = symp;
			defobj = &obj_rtld;
		}
    }

    if (def != NULL)
	*defobj_out = defobj;

    return def;
}

/*
 * Search the symbol table of a shared object and all objects needed
 * by it for a symbol of the given name.  Search order is
 * breadth-first.  Returns a pointer to the symbol, or NULL if no
 * definition was found.
 */
static const Elf_Sym *
symlook_needed(const char *name, unsigned long hash, const Needed_Entry *needed,
  const Obj_Entry **defobj_out, const Ver_Entry *ventry, int flags,
  DoneList *dlp)
{
    const Elf_Sym *def, *def_w;
    const Needed_Entry *n;
    const Obj_Entry *obj, *defobj, *defobj1;

    def = def_w = NULL;
    defobj = NULL;
    for (n = needed; n != NULL; n = n->next) {
	if ((obj = n->obj) == NULL ||
	    donelist_check(dlp, obj) ||
	    (def = symlook_obj(name, hash, obj, ventry, flags)) == NULL)
	    continue;
	defobj = obj;
	if (ELF_ST_BIND(def->st_info) != STB_WEAK) {
	    *defobj_out = defobj;
	    return (def);
	}
    }
    /*
     * There we come when either symbol definition is not found in
     * directly needed objects, or found symbol is weak.
     */
    for (n = needed; n != NULL; n = n->next) {
	if ((obj = n->obj) == NULL)
	    continue;
	def_w = symlook_needed(name, hash, obj->needed, &defobj1,
			       ventry, flags, dlp);
	if (def_w == NULL)
	    continue;
	if (def == NULL || ELF_ST_BIND(def_w->st_info) != STB_WEAK) {
	    def = def_w;
	    defobj = defobj1;
	}
	if (ELF_ST_BIND(def_w->st_info) != STB_WEAK)
	    break;
    }
    if (def != NULL)
	*defobj_out = defobj;
    return (def);
}

/*
 * Given a symbol number in a referencing object, find the corresponding
 * definition of the symbol.  Returns a pointer to the symbol, or NULL if
 * no definition was found.  Returns a pointer to the Obj_Entry of the
 * defining object via the reference parameter DEFOBJ_OUT.
 */
const Elf_Sym *
find_symdef(unsigned long symnum, const Obj_Entry *refobj,
    const Obj_Entry **defobj_out, int flags, SymCache *cache)
{
    const Elf_Sym *ref;
    const Elf_Sym *def;
    const Obj_Entry *defobj;
    const Ver_Entry *ventry;
    const char *name;
    unsigned long hash = 0;

    /*
     * If we have already found this symbol, get the information from
     * the cache.
     */
    if (symnum >= refobj->nchains && (refobj->gnu_bitmask == NULL))
	return NULL;	/* Bad object */
    if (cache != NULL && cache[symnum].sym != NULL) {
	*defobj_out = cache[symnum].obj;
	return cache[symnum].sym;
    }

    ref = refobj->symtab + symnum;
    name = refobj->strtab + ref->st_name;
    defobj = NULL;

    /*
     * We don't have to do a full scale lookup if the symbol is local.
     * We know it will bind to the instance in this load module; to
     * which we already have a pointer (ie ref). By not doing a lookup,
     * we not only improve performance, but it also avoids unresolvable
     * symbols when local symbols are not in the hash table. This has
     * been seen with the ia64 toolchain.
     */
    if (ELF_ST_BIND(ref->st_info) != STB_LOCAL) {
	if (ELF_ST_TYPE(ref->st_info) == STT_SECTION) {
	    _rtld_error("%s: Bogus symbol table entry %lu", refobj->path,
		symnum);
	}
	ventry = fetch_ventry(refobj, symnum);
	hash = elf_hash(name);
	def = symlook_default(name, hash, refobj, &defobj, ventry, flags);
    } else {
	def = ref;
	defobj = refobj;
    }

    /*
     * If we found no definition and the reference is weak, treat the
     * symbol as having the value zero.
     */
    if (def == NULL && ELF_ST_BIND(ref->st_info) == STB_WEAK) {
	def = &sym_zero;
	defobj = obj_main;
    }

    if (def != NULL) {
	*defobj_out = defobj;
	/* Record the information in the cache to avoid subsequent lookups. */
	if (cache != NULL) {
	    cache[symnum].sym = def;
	    cache[symnum].obj = defobj;
	}
    } else {
	if (refobj != &obj_rtld)
	    _rtld_error("%s: Undefined symbol \"%s\"", refobj->path, name);
    }
    return def;
}

/*
 * Get address of the pointer variable in the main program.
 */
static const void **
get_program_var_addr(const char *name)
{
    const Obj_Entry *obj;
    unsigned long hash;

    hash = elf_hash(name);
    for (obj = obj_main;  obj != NULL;  obj = obj->next) {
	const Elf_Sym *def;

	if ((def = symlook_obj(name, hash, obj, NULL, 0)) != NULL) {
	    const void **addr;

	    addr = (const void **)(obj->relocbase + def->st_value);
	    return addr;
	}
    }
    return NULL;
}

/*
 * Set a pointer variable in the main program to the given value.  This
 * is used to set key variables such as "environ" before any of the
 * init functions are called.
 */
static void
set_program_var(const char *name, const void *value)
{
    const void **addr;

    if ((addr = get_program_var_addr(name)) != NULL) {
	dbg("\"%s\": *%p <-- %p", name, addr, value);
	*addr = value;
    }
}

Elf_Addr
_rtld_bind(Obj_Entry *obj, Elf_Size reloff)
{
    const Elf_Rel *rel;
    const Elf_Sym *def;
    const Obj_Entry *defobj;
    Elf_Addr *where;
    Elf_Addr target;
    int lockstate;

    lockstate = rlock_acquire(late_rtld_bind_lock);
    if (obj->pltrel)
	rel = (const Elf_Rel *) ((caddr_t) obj->pltrel + reloff);
    else
	rel = (const Elf_Rel *) ((caddr_t) obj->pltrela + reloff);

    where = (Elf_Addr *) (obj->relocbase + rel->r_offset);
    def = find_symdef(ELF_R_SYM(rel->r_info), obj, &defobj, true, NULL);
    if (def == NULL)
	die();

    target = (Elf_Addr)(defobj->relocbase + def->st_value);

    dbg("\"%s\" in \"%s\" ==> %p in \"%s\"",
      defobj->strtab + def->st_name, basename(obj->path),
      (void *)target, basename(defobj->path));

    /*
     * Write the new contents for the jmpslot. Note that depending on
     * architecture, the value which we need to return back to the
     * lazy binding trampoline may or may not be the target
     * address. The value returned from reloc_jmpslot() is the value
     * that the trampoline needs.
     */
    target = reloc_jmpslot(where, target, defobj, obj, rel);
    rlock_release(late_rtld_bind_lock, lockstate);
    return target;
}

/*
 * Return a dynamically-allocated copy of the current error message, if any.
 */
static char *
errmsg_save(void)
{
    return error_message == NULL ? NULL : xstrdup(error_message);
}

/*
 * Restore the current error message from a copy which was previously saved
 * by errmsg_save().  The copy is freed.
 */
static void
errmsg_restore(char *saved_msg)
{
    if (saved_msg == NULL)
	error_message = NULL;
    else {
	_rtld_error("%s", saved_msg);
	free(saved_msg);
    }
}

/*
 * Call the initialization functions for each of the objects in
 * "list".  All of the objects are expected to have non-NULL init
 * functions.
 */
static void
objlist_call_init(Objlist *list, int *lockstate)
{
    Objlist_Entry *elm;
    Obj_Entry *obj;
    char *saved_msg = NULL;

    /*
     * Clean init_scanned flag so that objects can be rechecked and
     * possibly initialized earlier if any of vectors called below
     * cause the change by using dlopen.
     */
    for (obj = obj_list;  obj != NULL;  obj = obj->next)
	obj->init_scanned = false;

    STAILQ_FOREACH(elm, list, link) {
	if (elm->obj->init_done) /* Initialized early. */
	    continue;
	dbg("calling init function for %s at %p", elm->obj->path,
	    (void *)elm->obj->init);
	LD_UTRACE(UTRACE_INIT_CALL, elm->obj, (void *)elm->obj->init, 0, 0,
	    elm->obj->path);
	/*
	 * Race: other thread might try to use this object before current
	 * one completes the initilization. Not much can be done here
	 * without better locking.
	 */
	elm->obj->init_done = true;
    	wlock_release(late_rtld_bind_lock, *lockstate);
	call_initfini_pointer(elm->obj, elm->obj->init);
	*lockstate = wlock_acquire(late_rtld_bind_lock);
    }
    errmsg_restore(saved_msg);
}

static void
objlist_clear(Objlist *list)
{
    Objlist_Entry *elm;

    while (!STAILQ_EMPTY(list)) {
	elm = STAILQ_FIRST(list);
	STAILQ_REMOVE_HEAD(list, link);
	free(elm);
    }
}

static Objlist_Entry *
objlist_find(Objlist *list, const Obj_Entry *obj)
{
    Objlist_Entry *elm;

    STAILQ_FOREACH(elm, list, link)
	if (elm->obj == obj)
	    return elm;
    return NULL;
}

static void
objlist_init(Objlist *list)
{
    STAILQ_INIT(list);
}

static void
objlist_push_head(Objlist *list, Obj_Entry *obj)
{
    Objlist_Entry *elm;

    elm = NEW(Objlist_Entry);
    elm->obj = obj;
    STAILQ_INSERT_HEAD(list, elm, link);
}

static void
objlist_push_tail(Objlist *list, Obj_Entry *obj)
{
    Objlist_Entry *elm;

    elm = NEW(Objlist_Entry);
    elm->obj = obj;
    STAILQ_INSERT_TAIL(list, elm, link);
}

static void
objlist_remove(Objlist *list, Obj_Entry *obj)
{
    Objlist_Entry *elm;

    if ((elm = objlist_find(list, obj)) != NULL) {
	STAILQ_REMOVE(list, elm, Struct_Objlist_Entry, link);
	free(elm);
    }
}

static Obj_Entry *
obj_from_addr(const void *addr)
{
    Obj_Entry *obj;

    for (obj = obj_list;  obj != NULL;  obj = obj->next) {
	if (addr < (void *) obj->mapbase)
	    continue;
	if (addr < (void *) (obj->mapbase + obj->mapsize))
	    return obj;
    }
    return NULL;
}

/*
 * Call the finalization functions for each of the objects in "list"
 * which are unreferenced.  All of the objects are expected to have
 * non-NULL fini functions.
 */
static void
objlist_call_fini(Objlist *list, bool force, int *lockstate)
{
    Objlist_Entry *elm, *elm_tmp;
    char *saved_msg;

    /*
     * Preserve the current error message since a fini function might
     * call into the dynamic linker and overwrite it.
     */
    saved_msg = errmsg_save();
    STAILQ_FOREACH_SAFE(elm, list, link, elm_tmp) {
	if (elm->obj->refcount == 0 || force) {
	    dbg("calling fini function for %s at %p", elm->obj->path,
	        (void *)elm->obj->fini);
	    LD_UTRACE(UTRACE_FINI_CALL, elm->obj, (void *)elm->obj->fini, 0, 0,
		elm->obj->path);
	    /* Remove object from fini list to prevent recursive invocation. */
	    STAILQ_REMOVE(list, elm, Struct_Objlist_Entry, link);
	    wlock_release(late_rtld_bind_lock, *lockstate);
	    call_initfini_pointer(elm->obj, elm->obj->fini);
	    *lockstate = wlock_acquire(late_rtld_bind_lock);
	    /* No need to free anything if process is going down. */
	    if (!force)
	    	free(elm);
	}
    }
    errmsg_restore(saved_msg);
}

static void
linkmap_add(Obj_Entry *obj)
{
    struct link_map *l = &obj->linkmap;
    struct link_map *prev;

    obj->linkmap.l_name = obj->path;
    obj->linkmap.l_addr = obj->mapbase;
    obj->linkmap.l_ld = obj->dynamic;
#ifdef __mips__
    /* GDB needs load offset on MIPS to use the symbols */
    obj->linkmap.l_offs = obj->relocbase;
#endif

    if (r_debug.r_map == NULL) {
	r_debug.r_map = l;
	return;
    }

    /*
     * Scan to the end of the list, but not past the entry for the
     * dynamic linker, which we want to keep at the very end.
     */
    for (prev = r_debug.r_map;
      prev->l_next != NULL && prev->l_next != &obj_rtld.linkmap;
      prev = prev->l_next)
	;

    /* Link in the new entry. */
    l->l_prev = prev;
    l->l_next = prev->l_next;
    if (l->l_next != NULL)
	l->l_next->l_prev = l;
    prev->l_next = l;
}

static void
linkmap_delete(Obj_Entry *obj)
{
    struct link_map *l = &obj->linkmap;

    if (l->l_prev == NULL) {
	if ((r_debug.r_map = l->l_next) != NULL)
	    l->l_next->l_prev = NULL;
	return;
    }

    if ((l->l_prev->l_next = l->l_next) != NULL)
	l->l_next->l_prev = l->l_prev;
}

/*
 * Function for the debugger to set a breakpoint on to gain control.
 *
 * The two parameters allow the debugger to easily find and determine
 * what the runtime loader is doing and to whom it is doing it.
 *
 * When the loadhook trap is hit (r_debug_state, set at program
 * initialization), the arguments can be found on the stack:
 *
 *  +8   struct link_map *m
 *  +4   struct r_debug  *rd
 *  +0   RetAddr
 */
void
r_debug_state(struct r_debug* rd, struct link_map *m)
{
}

static void
unlink_object(Obj_Entry *root)
{
    Objlist_Entry *elm;

    if (root->refcount == 0) {
	/* Remove the object from the RTLD_GLOBAL list. */
	objlist_remove(&list_global, root);

    	/* Remove the object from all objects' DAG lists. */
    	STAILQ_FOREACH(elm, &root->dagmembers, link) {
	    objlist_remove(&elm->obj->dldags, root);
	    if (elm->obj != root)
		unlink_object(elm->obj);
	}
    }
}

/*
 * Unload a dlopened object and its dependencies from memory and from
 * our data structures.  It is assumed that the DAG rooted in the
 * object has already been unreferenced, and that the object has a
 * reference count of 0.
 */
static void
unload_object(Obj_Entry *root)
{
    Obj_Entry *obj;
    Obj_Entry **linkp;

    assert(root->refcount == 0);

    /*
     * Pass over the DAG removing unreferenced objects from
     * appropriate lists.
     */
    unlink_object(root);

    /* Unmap all objects that are no longer referenced. */
    linkp = &obj_list->next;
    while ((obj = *linkp) != NULL) {
	if (obj->refcount == 0) {
	    LD_UTRACE(UTRACE_UNLOAD_OBJECT, obj, obj->mapbase, obj->mapsize, 0,
		obj->path);
	    dbg("unloading \"%s\"", obj->path);
	    munmap(obj->mapbase, obj->mapsize);
	    linkmap_delete(obj);
	    *linkp = obj->next;
	    obj_count--;
	    obj_free(obj);
	} else
	    linkp = &obj->next;
    }
    obj_tail = linkp;
}

static void
ref_dag(Obj_Entry *root)
{
    Objlist_Entry *elm;

    STAILQ_FOREACH(elm, &root->dagmembers, link)
	elm->obj->refcount++;
}

static void
unref_dag(Obj_Entry *root)
{
    Objlist_Entry *elm;

    STAILQ_FOREACH(elm, &root->dagmembers, link)
	elm->obj->refcount--;
}

static void
init_dag1(Obj_Entry *root, Obj_Entry *obj, DoneList *dlp)
{
    const Needed_Entry *needed;

    if (donelist_check(dlp, obj))
	return;

    obj->refcount++;
    objlist_push_tail(&obj->dldags, root);
    objlist_push_tail(&root->dagmembers, obj);
    for (needed = obj->needed;  needed != NULL;  needed = needed->next)
	if (needed->obj != NULL)
	    init_dag1(root, needed->obj, dlp);
}

static void
init_dag(Obj_Entry *root)
{
    DoneList donelist;

    donelist_init(&donelist);
    init_dag1(root, root, &donelist);
}

/*
 * Add the init functions from a needed object list (and its recursive
 * needed objects) to "list".  This is not used directly; it is a helper
 * function for initlist_add_objects().  The write lock must be held
 * when this function is called.
 */
static void
initlist_add_neededs(Needed_Entry *needed, Objlist *list)
{
    /* Recursively process the successor needed objects. */
    if (needed->next != NULL)
	initlist_add_neededs(needed->next, list);

    /* Process the current needed object. */
    if (needed->obj != NULL)
	initlist_add_objects(needed->obj, &needed->obj->next, list);
}

/*
 * Scan all of the DAGs rooted in the range of objects from "obj" to
 * "tail" and add their init functions to "list".  This recurses over
 * the DAGs and ensure the proper init ordering such that each object's
 * needed libraries are initialized before the object itself.  At the
 * same time, this function adds the objects to the global finalization
 * list "list_fini" in the opposite order.  The write lock must be
 * held when this function is called.
 */
static void
initlist_add_objects(Obj_Entry *obj, Obj_Entry **tail, Objlist *list)
{
    if (obj->init_scanned || obj->init_done)
	return;
    obj->init_scanned = true;

    /* Recursively process the successor objects. */
    if (&obj->next != tail)
	initlist_add_objects(obj->next, tail, list);

    /* Recursively process the needed objects. */
    if (obj->needed != NULL)
	initlist_add_neededs(obj->needed, list);

    /* Add the object to the init list. */
    if (obj->init != (Elf_Addr)NULL)
	objlist_push_tail(list, obj);

    /* Add the object to the global fini list in the reverse order. */
    if (obj->fini != (Elf_Addr)NULL && !obj->on_fini_list) {
	objlist_push_head(&list_fini, obj);
	obj->on_fini_list = true;
    }
}

static void
object_add_name(Obj_Entry *obj, const char *name)
{
    Name_Entry *entry;
    size_t len;

    len = strlen(name);
    entry = malloc(sizeof(Name_Entry) + len);

    if (entry != NULL) {
	strcpy(entry->name, name);
	STAILQ_INSERT_TAIL(&obj->names, entry, link);
    }
}

/*
 * Process a shared object's DYNAMIC section, and save the important
 * information in its Obj_Entry structure.
 */
static void
digest_dynamic(Obj_Entry *obj, int early)
{
    const Elf_Dyn *dynp;
    Needed_Entry **needed_tail = &obj->needed;
    const Elf_Dyn *dyn_rpath = NULL;
    const Elf_Dyn *dyn_soname = NULL;
    int plttype = DT_REL;

    obj->bind_now = false;
    for (dynp = obj->dynamic;  dynp->d_tag != DT_NULL;  dynp++) {
	switch (dynp->d_tag) {

	case DT_REL:
	    obj->rel = (const Elf_Rel *) (obj->relocbase + dynp->d_un.d_ptr);
	    break;

	case DT_RELSZ:
	    obj->relsize = dynp->d_un.d_val;
	    break;

	case DT_RELENT:
	    assert(dynp->d_un.d_val == sizeof(Elf_Rel));
	    break;

	case DT_JMPREL:
	    obj->pltrel = (const Elf_Rel *)
	      (obj->relocbase + dynp->d_un.d_ptr);
	    break;

	case DT_PLTRELSZ:
	    obj->pltrelsize = dynp->d_un.d_val;
	    break;

	case DT_RELA:
	    obj->rela = (const Elf_Rela *) (obj->relocbase + dynp->d_un.d_ptr);
	    break;

	case DT_RELASZ:
	    obj->relasize = dynp->d_un.d_val;
	    break;

	case DT_RELAENT:
	    assert(dynp->d_un.d_val == sizeof(Elf_Rela));
	    break;

	case DT_PLTREL:
	    plttype = dynp->d_un.d_val;
	    assert(dynp->d_un.d_val == DT_REL || plttype == DT_RELA);
	    break;

	case DT_SYMTAB:
	    obj->symtab = (const Elf_Sym *)
	      (obj->relocbase + dynp->d_un.d_ptr);
	    break;

	case DT_SYMENT:
	    assert(dynp->d_un.d_val == sizeof(Elf_Sym));
	    break;

	case DT_STRTAB:
	    obj->strtab = (const char *) (obj->relocbase + dynp->d_un.d_ptr);
	    break;

	case DT_STRSZ:
	    obj->strsize = dynp->d_un.d_val;
	    break;

	case DT_VERNEED:
	    obj->verneed = (const Elf_Verneed *) (obj->relocbase +
		dynp->d_un.d_val);
	    break;

	case DT_VERNEEDNUM:
	    obj->verneednum = dynp->d_un.d_val;
	    break;

	case DT_VERDEF:
	    obj->verdef = (const Elf_Verdef *) (obj->relocbase +
		dynp->d_un.d_val);
	    break;

	case DT_VERDEFNUM:
	    obj->verdefnum = dynp->d_un.d_val;
	    break;

	case DT_VERSYM:
	    obj->versyms = (const Elf_Versym *)(obj->relocbase +
		dynp->d_un.d_val);
	    break;

	case DT_GNU_HASH:    
	{
		Elf32_Word *hashtab = (Elf32_Word *)(obj->relocbase + dynp->d_un.d_ptr);
		Elf32_Word symbias; 
		Elf32_Word maskwords; 

		obj->nbuckets = *hashtab++;
		symbias = *hashtab++;
		maskwords = *hashtab++;
		obj->gnu_bitmask_idxbits = maskwords - 1;
		obj->gnu_shift = *hashtab++;
		obj->gnu_bitmask = hashtab;
		hashtab += __ELF_WORD_SIZE / 32 * maskwords;
		obj->gnu_buckets = hashtab;
		hashtab += obj->nbuckets;
		obj->gnu_chain_zero = hashtab - symbias;
	    
	    }
	    break;
	case DT_HASH:
	    {
		const Elf_Hashelt *hashtab = (const Elf_Hashelt *)
		  (obj->relocbase + dynp->d_un.d_ptr);
		obj->nbuckets = hashtab[0];
		obj->nchains = hashtab[1];
		obj->buckets = hashtab + 2;
		obj->chains = obj->buckets + obj->nbuckets;
	    }
	    break;
	case DT_NEEDED:
	    if (!obj->rtld) {
		Needed_Entry *nep = NEW(Needed_Entry);
		nep->name = dynp->d_un.d_val;
		nep->obj = NULL;
		nep->next = NULL;

		*needed_tail = nep;
		needed_tail = &nep->next;
	    }
	    break;

	case DT_PLTGOT:
	    obj->pltgot = (Elf_Addr *) (obj->relocbase + dynp->d_un.d_ptr);
	    break;

	case DT_TEXTREL:
	    obj->textrel = true;
	    break;

	case DT_SYMBOLIC:
	    obj->symbolic = true;
	    break;

	case DT_RPATH:
	case DT_RUNPATH:	/* XXX: process separately */
	    /*
	     * We have to wait until later to process this, because we
	     * might not have gotten the address of the string table yet.
	     */
	    dyn_rpath = dynp;
	    break;

	case DT_SONAME:
	    dyn_soname = dynp;
	    break;

	case DT_INIT:
	    obj->init = (Elf_Addr) (obj->relocbase + dynp->d_un.d_ptr);
	    break;

	case DT_FINI:
	    obj->fini = (Elf_Addr) (obj->relocbase + dynp->d_un.d_ptr);
	    break;

	/*
	 * Don't process DT_DEBUG on MIPS as the dynamic section
	 * is mapped read-only. DT_MIPS_RLD_MAP is used instead.
	 */

#ifndef __mips__
	case DT_DEBUG:
	    /* XXX - not implemented yet */
	    if (!early)
		dbg("Filling in DT_DEBUG entry");
	    ((Elf_Dyn*)dynp)->d_un.d_ptr = (Elf_Addr) &r_debug;
	    break;
#endif

	case DT_FLAGS:
		if ((dynp->d_un.d_val & DF_ORIGIN) && trust)
		    obj->z_origin = true;
		if (dynp->d_un.d_val & DF_SYMBOLIC)
		    obj->symbolic = true;
		if (dynp->d_un.d_val & DF_TEXTREL)
		    obj->textrel = true;
		if (dynp->d_un.d_val & DF_BIND_NOW)
		    obj->bind_now = true;
		if (dynp->d_un.d_val & DF_STATIC_TLS)
		    ;
	    break;
#ifdef __mips__
	case DT_MIPS_LOCAL_GOTNO:
		obj->local_gotno = dynp->d_un.d_val;
	    break;

	case DT_MIPS_SYMTABNO:
		obj->symtabno = dynp->d_un.d_val;
		break;

	case DT_MIPS_GOTSYM:
		obj->gotsym = dynp->d_un.d_val;
		break;

	case DT_MIPS_RLD_MAP:
#ifdef notyet
		if (!early)
			dbg("Filling in DT_DEBUG entry");
		((Elf_Dyn*)dynp)->d_un.d_ptr = (Elf_Addr) &r_debug;
#endif
		break;
#endif
#if 0
	case DT_FLAGS_1:
		if ((dynp->d_un.d_val & DF_1_ORIGIN) && trust)
		    obj->z_origin = true;
		if (dynp->d_un.d_val & DF_1_GLOBAL)
			/* XXX */;
		if (dynp->d_un.d_val & DF_1_BIND_NOW)
		    obj->bind_now = true;
		if (dynp->d_un.d_val & DF_1_NODELETE)
		    obj->z_nodelete = true;
	    break;
#endif
	default:
	    if (!early) {
		dbg("Ignoring d_tag %ld = %#lx", (long)dynp->d_tag,
		    (long)dynp->d_tag);
	    }
	    break;
	}
    }

    obj->traced = false;

    if (plttype == DT_RELA) {
	obj->pltrela = (const Elf_Rela *) obj->pltrel;
	obj->pltrel = NULL;
	obj->pltrelasize = obj->pltrelsize;
	obj->pltrelsize = 0;
    }

    if (dyn_soname != NULL)
	object_add_name(obj, obj->strtab + dyn_soname->d_un.d_val);
}

static Obj_Entry *
do_load_object(const char *name, unsigned char *ibuf, ssize_t isize)
{
    Obj_Entry *obj = NULL;
    ssize_t size = isize;
    int ret;
    unsigned char *buf = ibuf;
    Obj_Entry **objp = &obj;
    
    if ((buf == NULL) && open_object(name, &buf, &size, objp))
	    return (NULL);

    if (obj != NULL)
	    return (obj);

    dbg("loading \"%s\"", path);
    obj = map_object(name, buf, size);
    if (obj == NULL)
	    return NULL;

    set_object(name, obj);
    object_add_name(obj, name);
    obj->path = NULL;
    digest_dynamic(obj, 0);

    *obj_tail = obj;
    obj_tail = &obj->next;
    obj_count++;
    obj_loads++;
    linkmap_add(obj);	/* for GDB & dlinfo() */

    dbg("  %p .. %p: %s", obj->mapbase,
         obj->mapbase + obj->mapsize - 1, obj->path);
    if (obj->textrel)
	dbg("  WARNING: %s has impure text", obj->path);
    LD_UTRACE(UTRACE_LOAD_OBJECT, obj, obj->mapbase, obj->mapsize, 0,
	obj->path);    

    return obj;
}

/*
 * Load a shared object into memory, if it is not already loaded.
 *
 * Returns a pointer to the Obj_Entry for the object.  Returns NULL
 * on failure.
 */
static Obj_Entry *
load_object(const char *name, const Obj_Entry *refobj,
    unsigned char *buf, ssize_t len)
{
    Obj_Entry *obj;
    int fd = -1;
    char *path;

    for (obj = obj_list->next;  obj != NULL;  obj = obj->next)
	if (object_match_name(obj, name))
	    return obj;


    if (obj != NULL) {
	object_add_name(obj, name);
	return obj;
    }

    /* First use of this object, so we must map it in */
    obj = do_load_object(name, buf, len);

    return obj;
}

/*
 * Given a shared object, traverse its list of needed objects, and load
 * each of them.  Returns 0 on success.  Generates an error message and
 * returns -1 on failure.
 */
static int
load_needed_objects(Obj_Entry *first)
{
    Obj_Entry *obj, *obj1;

    for (obj = first;  obj != NULL;  obj = obj->next) {
	Needed_Entry *needed;

	for (needed = obj->needed;  needed != NULL;  needed = needed->next) {
	    obj1 = needed->obj = load_object(obj->strtab + needed->name,
		obj, NULL, 0);
	    if (obj1 == NULL && !ld_tracing)
		return -1;
	    if (obj1 != NULL && obj1->z_nodelete && !obj1->ref_nodel) {
		dbg("obj %s nodelete", obj1->path);
		init_dag(obj1);
		ref_dag(obj1);
		obj1->ref_nodel = true;
	    }
	}
    }

    return 0;
}

/*
 * Process a shared object's program header.  This is used only for the
 * main program, when the kernel has already loaded the main program
 * into memory before calling the dynamic linker.  It creates and
 * returns an Obj_Entry structure.
 */
static Obj_Entry *
digest_phdr(const Elf_Phdr *phdr, int phnum, caddr_t entry, const char *path)
{
    Obj_Entry *obj;
    const Elf_Phdr *phlimit = phdr + phnum;
    const Elf_Phdr *ph;
    int nsegs = 0;

    obj = obj_new();
    for (ph = phdr;  ph < phlimit;  ph++) {
	switch (ph->p_type) {

	case PT_PHDR:
	    if ((const Elf_Phdr *)ph->p_vaddr != phdr) {
		_rtld_error("%s: invalid PT_PHDR", path);
		return NULL;
	    }
	    obj->phdr = (const Elf_Phdr *) ph->p_vaddr;
	    obj->phsize = ph->p_memsz;
	    break;

	case PT_INTERP:
	    obj->interp = (const char *) ph->p_vaddr;
	    break;

	case PT_LOAD:
	    if (nsegs == 0) {	/* First load segment */
		obj->vaddrbase = trunc_page(ph->p_vaddr);
		obj->mapbase = (caddr_t) obj->vaddrbase;
		obj->relocbase = obj->mapbase - obj->vaddrbase;
		obj->textsize = round_page(ph->p_vaddr + ph->p_memsz) -
		  obj->vaddrbase;
	    } else {		/* Last load segment */
		obj->mapsize = round_page(ph->p_vaddr + ph->p_memsz) -
		  obj->vaddrbase;
	    }
	    nsegs++;
	    break;

	case PT_DYNAMIC:
	    obj->dynamic = (const Elf_Dyn *) ph->p_vaddr;
	    break;

	case PT_TLS:
	    obj->tlsindex = 1;
	    obj->tlssize = ph->p_memsz;
	    obj->tlsalign = ph->p_align;
	    obj->tlsinitsize = ph->p_filesz;
	    obj->tlsinit = (void*) ph->p_vaddr;
	    break;
	}
    }
    if (nsegs < 1) {
	_rtld_error("%s: too few PT_LOAD segments", path);
	return NULL;
    }

    obj->entry = entry;
    return obj;
}

/*
 * Relocate newly-loaded shared objects.  The argument is a pointer to
 * the Obj_Entry for the first such object.  All objects from the first
 * to the end of the list of objects are relocated.  Returns 0 on success,
 * or -1 on failure.
 */
static int
relocate_objects(Obj_Entry *first, bool bind_now, Obj_Entry *rtldobj)
{
    Obj_Entry *obj;

    for (obj = first;  obj != NULL;  obj = obj->next) {
	if (obj != rtldobj)
	    dbg("relocating \"%s\"", obj->path);
	if (obj->nbuckets == 0 || ((obj->nchains == 0 || obj->buckets == NULL)
		&& ((obj->gnu_bitmask == NULL) || obj->gnu_buckets == NULL)) &&
	    obj->symtab == NULL || obj->strtab == NULL) {
	    _rtld_error("%s: Shared object has no run-time symbol table",
	      obj->path);
	    return -1;
	}

	if (obj->textrel) {
	    /* There are relocations to the write-protected text segment. */
	    if (mprotect(obj->mapbase, obj->textsize,
	      PROT_READ|PROT_WRITE|PROT_EXEC) == -1) {
		_rtld_error("%s: Cannot write-enable text segment: %s",
		  obj->path, strerror(errno));
		return -1;
	    }
	}

	/* Process the non-PLT relocations. */
	if (reloc_non_plt(obj, rtldobj))
		return -1;

	if (obj->textrel) {	/* Re-protected the text segment. */
	    if (mprotect(obj->mapbase, obj->textsize,
	      PROT_READ|PROT_EXEC) == -1) {
		_rtld_error("%s: Cannot write-protect text segment: %s",
		  obj->path, strerror(errno));
		return -1;
	    }
	}

	/* Process the PLT relocations. */
	if (reloc_plt(obj) == -1)
	    return -1;
	/* Relocate the jump slots if we are doing immediate binding. */
	if (obj->bind_now || bind_now)
	    if (reloc_jmpslots(obj) == -1)
		return -1;


	/*
	 * Set up the magic number and version in the Obj_Entry.  These
	 * were checked in the crt1.o from the original ElfKit, so we
	 * set them for backward compatibility.
	 */
	obj->magic = RTLD_MAGIC;
	obj->version = RTLD_VERSION;

	/* Set the special PLT or GOT entries. */
	init_pltgot(obj);
    }

    return 0;
}

/*
 * Initialize the dynamic linker.  The argument is the address at which
 * the dynamic linker has been mapped into memory.  The primary task of
 * this function is to relocate the dynamic linker.
 */
static void
init_rtld(caddr_t mapbase)
{
    Obj_Entry objtmp;	/* Temporary rtld object */

    /*
     * Conjure up an Obj_Entry structure for the dynamic linker.
     *
     * The "path" member can't be initialized yet because string constants
     * cannot yet be accessed. Below we will set it correctly.
     */
    memset(&objtmp, 0, sizeof(objtmp));
    objtmp.path = NULL;
    objtmp.rtld = true;
    objtmp.mapbase = mapbase;
#ifdef PIC
    objtmp.relocbase = mapbase;
#endif
    if (RTLD_IS_DYNAMIC()) {
	objtmp.dynamic = rtld_dynamic(&objtmp);
	digest_dynamic(&objtmp, 1);
	assert(objtmp.needed == NULL);
#if !defined(__mips__)
	/* MIPS and SH{3,5} have a bogus DT_TEXTREL. */
	assert(!objtmp.textrel);
#endif

	/*
	 * Temporarily put the dynamic linker entry into the object list, so
	 * that symbols can be found.
	 */

	relocate_objects(&objtmp, true, &objtmp);
    }

    /* Initialize the object list. */
    obj_tail = &obj_list;

    /* Now that non-local variables can be accesses, copy out obj_rtld. */
    memcpy(&obj_rtld, &objtmp, sizeof(obj_rtld));

    /* Replace the path with a dynamically allocated copy. */
    obj_rtld.path = xstrdup(PATH_RTLD);

#if 0
    r_debug.r_brk = r_debug_state;
    r_debug.r_state = RT_CONSISTENT;
#endif
}

/*
 * Cleanup procedure.  It will be called (by the atexit mechanism) just
 * before the process exits.
 */
static void
rtld_exit(void)
{
    int	lockstate;

    lockstate = wlock_acquire(late_rtld_bind_lock);
    dbg("rtld_exit()");
    objlist_call_fini(&list_fini, true, &lockstate);
    /* No need to remove the items from the list, since we are exiting. */
    wlock_release(late_rtld_bind_lock, lockstate);
}
/*
 * Main entry point for dynamic linking.  The first argument is the
 * stack pointer.  The stack is expected to be laid out as described
 * in the SVR4 ABI specification, Intel 386 Processor Supplement.
 * Specifically, the stack pointer points to a word containing
 * ARGC.  Following that in the stack is a null-terminated sequence
 * of pointers to argument strings.  Then comes a null-terminated
 * sequence of pointers to environment strings.  Finally, there is a
 * sequence of "auxiliary vector" entries.
 *
 * The second argument points to a place to store the dynamic linker's
 * exit procedure pointer and the third to a place to store the main
 * program's object.
 *
 * The return value is the main program's entry point.
 */
func_ptr_type
_rtld_late(unsigned char *base, unsigned char *buf, ssize_t size, func_ptr_type *exit_proc, Obj_Entry **objp)
{
    int i;
    const char *argv0;
    Objlist_Entry *entry;
    Obj_Entry *obj;
    Obj_Entry **preload_tail;
    Objlist initlist;
    int lockstate;

    /*
     * On entry, the dynamic linker itself has not been relocated yet.
     * Be very careful not to reference any global data until after
     * init_rtld has returned.  It is OK to reference file-scope statics
     * and string constants, and to call static and global functions.
     */

    /* Initialize and relocate ourselves. */
    assert(buf != NULL);
    init_rtld((caddr_t) base);

    __late_progname = obj_rtld.path;
    argv0 = "unknown";
   
#if 0
    ld_tracing = getenv(LD_ "TRACE_LOADED_OBJECTS");
    ld_utrace = getenv(LD_ "UTRACE");
#endif

    if (ld_debug != NULL && *ld_debug != '\0')
	debug = 1;
    dbg("%s is initialized, base address = %p", __late_progname,
	(caddr_t) buf);
    dbg("RTLD dynamic = %p", obj_rtld.dynamic);
    dbg("RTLD pltgot  = %p", obj_rtld.pltgot);

    /*
     * Load the main program, or process its program header if it is
     * already loaded.
     */
    dbg("loading main program");
    obj_main = map_object(argv0, buf, size);
    if (obj_main == NULL)
	    die();

    dbg("No AT_EXECPATH");
    obj_main->path = xstrdup(argv0);
    dbg("obj_main path %s", obj_main->path);
    obj_main->mainprog = true;

#if 0
    /*
     * Get the actual dynamic linker pathname from the executable if
     * possible.  (It should always be possible.)  That ensures that
     * gdb will find the right dynamic linker even if a non-standard
     * one is being used.
     */
    if (obj_main->interp != NULL &&
      strcmp(obj_main->interp, obj_rtld.path) != 0) {
	free(obj_rtld.path);
	obj_rtld.path = xstrdup(obj_main->interp);
        __late_progname = obj_rtld.path;
    }
#endif
    digest_dynamic(obj_main, 0);

    linkmap_add(obj_main);
    linkmap_add(&obj_rtld);

    /* Link the main program into the list of objects. */
    *obj_tail = obj_main;
    obj_tail = &obj_main->next;
    obj_count++;
    obj_loads++;
    /* Make sure we don't call the main program's init and fini functions. */
    obj_main->init = obj_main->fini = (Elf_Addr)NULL;

    /* Initialize a fake symbol for resolving undefined weak references. */
    sym_zero.st_info = ELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
    sym_zero.st_shndx = SHN_UNDEF;

    preload_tail = obj_tail;

    dbg("loading needed objects");
    if (load_needed_objects(obj_main) == -1)
	die();

    /* Make a list of all objects loaded at startup. */
    for (obj = obj_list;  obj != NULL;  obj = obj->next) {
	objlist_push_tail(&list_main, obj);
    	obj->refcount++;
    }

    /* setup TLS for main thread */
    dbg("initializing initial thread local storage");
    STAILQ_FOREACH(entry, &list_main, link) {
	/*
	 * Allocate all the initial objects out of the static TLS
	 * block even if they didn't ask for it.
	 */
	allocate_tls_offset(entry->obj);
    }
    allocate_initial_tls(obj_list);

    if (relocate_objects(obj_main,
	ld_bind_now != NULL && *ld_bind_now != '\0', &obj_rtld) == -1)
	die();

    dbg("doing copy relocations");
    if (do_copy_relocations(obj_main) == -1)
	die();

    dbg("initializing key program variables");
    set_program_var("__late_progname", "0WNAGE");

    dbg("initializing thread locks");
    late_lockdflt_init();

    /* Make a list of init functions to call. */
    objlist_init(&initlist);
    initlist_add_objects(obj_list, preload_tail, &initlist);
    r_debug_state(NULL, &obj_main->linkmap); /* say hello to gdb! */
    lockstate = wlock_acquire(late_rtld_bind_lock);
    objlist_call_init(&initlist, &lockstate);
    objlist_clear(&initlist);
    wlock_release(late_rtld_bind_lock, lockstate);

    dbg("transferring control to program entry point = %p", obj_main->entry);

    /* Return the exit procedure and the program entry point. */
    *exit_proc = rtld_exit;
    *objp = obj_main;
    return (func_ptr_type) obj_main->entry;
}

static Obj_Entry *
dlcheck(void *handle)
{
    Obj_Entry *obj;

    for (obj = obj_list;  obj != NULL;  obj = obj->next)
	if (obj == (Obj_Entry *) handle)
	    break;

    if (obj == NULL || obj->refcount == 0 || obj->dl_refcount == 0) {
	_rtld_error("Invalid shared object handle %p", handle);
	return NULL;
    }
    return obj;
}

int
dlclose(void *handle)
{
    Obj_Entry *root;
    int lockstate;

    lockstate = wlock_acquire(late_rtld_bind_lock);
    root = dlcheck(handle);
    if (root == NULL) {
	wlock_release(late_rtld_bind_lock, lockstate);
	return -1;
    }
    LD_UTRACE(UTRACE_DLCLOSE_START, handle, NULL, 0, root->dl_refcount,
	root->path);

    /* Unreference the object and its dependencies. */
    root->dl_refcount--;

    unref_dag(root);

    if (root->refcount == 0) {
	/*
	 * The object is no longer referenced, so we must unload it.
	 * First, call the fini functions.
	 */
	objlist_call_fini(&list_fini, false, &lockstate);

	/* Finish cleaning up the newly-unreferenced objects. */
	GDB_STATE(RT_DELETE,&root->linkmap);
	unload_object(root);
	GDB_STATE(RT_CONSISTENT,NULL);
    }
    LD_UTRACE(UTRACE_DLCLOSE_STOP, handle, NULL, 0, 0, NULL);
    wlock_release(late_rtld_bind_lock, lockstate);
    return 0;
}

void *
dlopen(const char *name, int mode)
{
    Obj_Entry **old_obj_tail;
    Obj_Entry *obj;
    Objlist initlist;
    int result, lockstate, nodelete, noload;

    LD_UTRACE(UTRACE_DLOPEN_START, NULL, NULL, 0, mode, name);
    ld_tracing = (mode & RTLD_TRACE) == 0 ? NULL : "1";
    if (ld_tracing != NULL)
	environ = (char **)*get_program_var_addr("environ");
    nodelete = mode & RTLD_NODELETE;
    noload = mode & RTLD_NOLOAD;

    objlist_init(&initlist);

    lockstate = wlock_acquire(late_rtld_bind_lock);
    GDB_STATE(RT_ADD,NULL);

    old_obj_tail = obj_tail;
    obj = NULL;
    if (name == NULL) {
	obj = obj_main;
	obj->refcount++;
    } else {
	    obj = load_object(name, obj_main, NULL, 0);
    }

    if (obj) {
	obj->dl_refcount++;
	if (mode & RTLD_GLOBAL && objlist_find(&list_global, obj) == NULL)
	    objlist_push_tail(&list_global, obj);
	mode &= RTLD_MODEMASK;
	if (*old_obj_tail != NULL) {		/* We loaded something new. */
	    assert(*old_obj_tail == obj);
	    result = load_needed_objects(obj);
	    init_dag(obj);
#if 0
	    if (result != -1)
		result = rtld_verify_versions(&obj->dagmembers);
#endif
	    if (result != -1 && ld_tracing)
		goto trace;
	    if (result == -1 ||
	      (relocate_objects(obj, mode == RTLD_NOW, &obj_rtld)) == -1) {
		obj->dl_refcount--;
		unref_dag(obj);
		if (obj->refcount == 0)
		    unload_object(obj);
		obj = NULL;
	    } else {
		/* Make list of init functions to call. */
		initlist_add_objects(obj, &obj->next, &initlist);
	    }
	} else {

	    /* Bump the reference counts for objects on this DAG. */
	    ref_dag(obj);

	    if (ld_tracing)
		goto trace;
	}
	if (obj != NULL && (nodelete || obj->z_nodelete) && !obj->ref_nodel) {
	    dbg("obj %s nodelete", obj->path);
	    ref_dag(obj);
	    obj->z_nodelete = obj->ref_nodel = true;
	}
    }

    LD_UTRACE(UTRACE_DLOPEN_STOP, obj, NULL, 0, obj ? obj->dl_refcount : 0,
	name);
    GDB_STATE(RT_CONSISTENT,obj ? &obj->linkmap : NULL);

    /* Call the init functions. */
    objlist_call_init(&initlist, &lockstate);
    objlist_clear(&initlist);
    wlock_release(late_rtld_bind_lock, lockstate);
    return obj;
trace:
#if 0
    trace_loaded_objects(obj);
#endif
    wlock_release(late_rtld_bind_lock, lockstate);
    exit(0);
}

void *
dlopenbuf(const char *name, int mode, unsigned char *buf, size_t len)
{
    Obj_Entry **old_obj_tail;
    Obj_Entry *obj;
    Objlist initlist;
    int result, lockstate, nodelete, noload;

    LD_UTRACE(UTRACE_DLOPEN_START, NULL, NULL, 0, mode, name);
    ld_tracing = (mode & RTLD_TRACE) == 0 ? NULL : "1";
    if (ld_tracing != NULL)
	environ = (char **)*get_program_var_addr("environ");
    nodelete = mode & RTLD_NODELETE;
    noload = mode & RTLD_NOLOAD;

    objlist_init(&initlist);

    lockstate = wlock_acquire(late_rtld_bind_lock);
    GDB_STATE(RT_ADD,NULL);

    old_obj_tail = obj_tail;
    obj = NULL;
    if (name == NULL) {
	obj = obj_main;
	obj->refcount++;
    } else {
	    obj = load_object(name, obj_main, buf, len);
    }

    if (obj) {
	obj->dl_refcount++;
	if (mode & RTLD_GLOBAL && objlist_find(&list_global, obj) == NULL)
	    objlist_push_tail(&list_global, obj);
	mode &= RTLD_MODEMASK;
	if (*old_obj_tail != NULL) {		/* We loaded something new. */
	    assert(*old_obj_tail == obj);
	    result = load_needed_objects(obj);
	    init_dag(obj);
#if 0
	    if (result != -1)
		result = rtld_verify_versions(&obj->dagmembers);
#endif
	    if (result != -1 && ld_tracing)
		goto trace;
	    if (result == -1 ||
	      (relocate_objects(obj, mode == RTLD_NOW, &obj_rtld)) == -1) {
		obj->dl_refcount--;
		unref_dag(obj);
		if (obj->refcount == 0)
		    unload_object(obj);
		obj = NULL;
	    } else {
		/* Make list of init functions to call. */
		initlist_add_objects(obj, &obj->next, &initlist);
	    }
	} else {

	    /* Bump the reference counts for objects on this DAG. */
	    ref_dag(obj);

	    if (ld_tracing)
		goto trace;
	}
	if (obj != NULL && (nodelete || obj->z_nodelete) && !obj->ref_nodel) {
	    dbg("obj %s nodelete", obj->path);
	    ref_dag(obj);
	    obj->z_nodelete = obj->ref_nodel = true;
	}
    }

    LD_UTRACE(UTRACE_DLOPEN_STOP, obj, NULL, 0, obj ? obj->dl_refcount : 0,
	name);
    GDB_STATE(RT_CONSISTENT,obj ? &obj->linkmap : NULL);

    /* Call the init functions. */
    objlist_call_init(&initlist, &lockstate);
    objlist_clear(&initlist);
    wlock_release(late_rtld_bind_lock, lockstate);
    return obj;
trace:
#if 0
    trace_loaded_objects(obj);
#endif
    wlock_release(late_rtld_bind_lock, lockstate);
    exit(0);
}

static void *
do_dlsym(void *handle, const char *name, void *retaddr, const Ver_Entry *ve,
    int flags)
{
    DoneList donelist;
    const Obj_Entry *obj, *defobj;
    const Elf_Sym *def, *symp;
    unsigned long hash;
    int lockstate;

    hash = elf_hash(name);
    def = NULL;
    defobj = NULL;
    flags |= SYMLOOK_IN_PLT;

    lockstate = rlock_acquire(late_rtld_bind_lock);
    if (handle == NULL || handle == RTLD_NEXT ||
	handle == RTLD_DEFAULT || handle == RTLD_SELF) {

	if ((obj = obj_from_addr(retaddr)) == NULL) {
	    _rtld_error("Cannot determine caller's shared object");
	    rlock_release(late_rtld_bind_lock, lockstate);
	    return NULL;
	}
	if (handle == NULL) {	/* Just the caller's shared object. */
	    def = symlook_obj(name, hash, obj, ve, flags);
	    defobj = obj;
	} else if (handle == RTLD_NEXT || /* Objects after caller's */
		   handle == RTLD_SELF) { /* ... caller included */
	    if (handle == RTLD_NEXT)
		obj = obj->next;
	    for (; obj != NULL; obj = obj->next) {
	    	if ((symp = symlook_obj(name, hash, obj, ve, flags)) != NULL) {
		    if (def == NULL || ELF_ST_BIND(symp->st_info) != STB_WEAK) {
			def = symp;
			defobj = obj;
			if (ELF_ST_BIND(def->st_info) != STB_WEAK)
			    break;
		    }
		}
	    }
	    /*
	     * Search the dynamic linker itself, and possibly resolve the
	     * symbol from there.  This is how the application links to
	     * dynamic linker services such as dlopen.  Only the values listed
	     * in the "exports" array can be resolved from the dynamic linker.
	     */
	    if (def == NULL || ELF_ST_BIND(def->st_info) == STB_WEAK) {
		symp = symlook_obj(name, hash, &obj_rtld, ve, flags);
		if (symp != NULL && is_exported(symp)) {
		    def = symp;
		    defobj = &obj_rtld;
		}
	    }
	} else {
	    assert(handle == RTLD_DEFAULT);
	    def = symlook_default(name, hash, obj, &defobj, ve, flags);
	}
    } else {
	if ((obj = dlcheck(handle)) == NULL) {
	    rlock_release(late_rtld_bind_lock, lockstate);
	    return NULL;
	}

	donelist_init(&donelist);
	if (obj->mainprog) {
	    /* Search main program and all libraries loaded by it. */
	    def = symlook_list(name, hash, &list_main, &defobj, ve, flags,
			       &donelist);

	    /*
	     * We do not distinguish between 'main' object and global scope.
	     * If symbol is not defined by objects loaded at startup, continue
	     * search among dynamically loaded objects with RTLD_GLOBAL
	     * scope.
	     */
	    if (def == NULL)
		def = symlook_list(name, hash, &list_global, &defobj, ve,
		    		    flags, &donelist);
	} else {
	    Needed_Entry fake;

	    /* Search the whole DAG rooted at the given object. */
	    fake.next = NULL;
	    fake.obj = (Obj_Entry *)obj;
	    fake.name = 0;
	    def = symlook_needed(name, hash, &fake, &defobj, ve, flags,
		&donelist);
	}
    }

    if (def != NULL) {
	rlock_release(late_rtld_bind_lock, lockstate);

	/*
	 * The value required by the caller is derived from the value
	 * of the symbol. For the ia64 architecture, we need to
	 * construct a function descriptor which the caller can use to
	 * call the function with the right 'gp' value. For other
	 * architectures and for non-functions, the value is simply
	 * the relocated value of the symbol.
	 */
	if (ELF_ST_TYPE(def->st_info) == STT_FUNC)
	    return make_function_pointer(def, defobj);
	else
	    return defobj->relocbase + def->st_value;
    }

    _rtld_error("Undefined symbol \"%s\"", name);
    rlock_release(late_rtld_bind_lock, lockstate);
    return NULL;
}

void *
dlsym(void *handle, const char *name)
{
	return do_dlsym(handle, name, __builtin_return_address(0), NULL,
	    SYMLOOK_DLSYM);
}
