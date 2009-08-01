/*-
 * Copyright 1996, 1997, 1998, 1999, 2000 John D. Polstra.
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
 * $FreeBSD: head/libexec/rtld-elf/rtld.h 194531 2009-06-20 14:16:41Z kan $
 */

#ifndef RTLD_H /* { */
#define RTLD_H 1

#define IN_LIBLOADER
#include <sys/link_elf.h>

#include <sys/queue.h>

#include "rtld_lock.h"
#include "rtld_machdep.h"

#ifdef COMPAT_32BIT
#undef STANDARD_LIBRARY_PATH
#undef _PATH_ELF_HINTS
#define	_PATH_ELF_HINTS		"/var/run/ld-elf32.so.hints"
/* For running 32 bit binaries  */
#define	STANDARD_LIBRARY_PATH	"/lib32:/usr/lib32"
#define LD_ "LD_32_"
#endif

#ifndef STANDARD_LIBRARY_PATH
#define STANDARD_LIBRARY_PATH	"/lib:/usr/lib"
#endif
#ifndef LD_
#define LD_ "LD_"
#endif

#define NEW(type)	((type *) xmalloc(sizeof(type)))
#define CNEW(type)	((type *) xcalloc(sizeof(type)))

/* We might as well do booleans like C++. */
typedef unsigned char bool;
#define false	0
#define true	1

extern size_t tls_last_offset;
extern size_t tls_last_size;
extern size_t tls_static_space;
extern int tls_dtv_generation;
extern int tls_max_index;
extern int __loader_socket;

struct stat;
struct Struct_Obj_Entry;

/* Lists of shared objects */
typedef struct Struct_Objlist_Entry {
    STAILQ_ENTRY(Struct_Objlist_Entry) link;
    struct Struct_Obj_Entry *obj;
} Objlist_Entry;

typedef STAILQ_HEAD(Struct_Objlist, Struct_Objlist_Entry) Objlist;

/* Types of init and fini functions */
typedef void (*InitFunc)(void);

/* Lists of shared object dependencies */
typedef struct Struct_Needed_Entry {
    struct Struct_Needed_Entry *next;
    struct Struct_Obj_Entry *obj;
    unsigned long name;		/* Offset of name in string table */
} Needed_Entry;

typedef struct Struct_Name_Entry {
    STAILQ_ENTRY(Struct_Name_Entry) link;
    char   name[1];
} Name_Entry;

/* Lock object */
typedef struct Struct_LockInfo {
    void *context;		/* Client context for creating locks */
    void *thelock;		/* The one big lock */
    /* Debugging aids. */
    volatile int rcount;	/* Number of readers holding lock */
    volatile int wcount;	/* Number of writers holding lock */
    /* Methods */
    void *(*lock_create)(void *context);
    void (*rlock_acquire)(void *lock);
    void (*wlock_acquire)(void *lock);
    void (*rlock_release)(void *lock);
    void (*wlock_release)(void *lock);
    void (*lock_destroy)(void *lock);
    void (*context_destroy)(void *context);
} LockInfo;

typedef struct Struct_Ver_Entry {
	Elf_Word     hash;
	unsigned int flags;
	const char  *name;
	const char  *file;
} Ver_Entry;

#define VER_INFO_HIDDEN	0x01

/*
 * Shared object descriptor.
 *
 * Items marked with "(%)" are dynamically allocated, and must be freed
 * when the structure is destroyed.
 *
 * CAUTION: It appears that the JDK port peeks into these structures.
 * It looks at "next" and "mapbase" at least.  Don't add new members
 * near the front, until this can be straightened out.
 */
typedef struct Struct_Obj_Entry {
    /*
     * These two items have to be set right for compatibility with the
     * original ElfKit crt1.o.
     */
    Elf_Size magic;		/* Magic number (sanity check) */
    Elf_Size version;		/* Version number of struct format */

    struct Struct_Obj_Entry *next;
    char *path;			/* Pathname of underlying file (%) */
    char *origin_path;		/* Directory path of origin file */
    int refcount;
    int dl_refcount;		/* Number of times loaded by dlopen */

    /* These items are computed by map_object() or by digest_phdr(). */
    caddr_t mapbase;		/* Base address of mapped region */
    size_t mapsize;		/* Size of mapped region in bytes */
    size_t textsize;		/* Size of text segment in bytes */
    Elf_Addr vaddrbase;		/* Base address in shared object file */
    caddr_t relocbase;		/* Relocation constant = mapbase - vaddrbase */
    const Elf_Dyn *dynamic;	/* Dynamic section */
    caddr_t entry;		/* Entry point */
    const Elf_Phdr *phdr;	/* Program header if it is mapped, else NULL */
    size_t phsize;		/* Size of program header in bytes */
    const char *interp;		/* Pathname of the interpreter, if any */

    /* TLS information */
    int tlsindex;		/* Index in DTV for this module */
    void *tlsinit;		/* Base address of TLS init block */
    size_t tlsinitsize;		/* Size of TLS init block for this module */
    size_t tlssize;		/* Size of TLS block for this module */
    size_t tlsoffset;		/* Offset of static TLS block for this module */
    size_t tlsalign;		/* Alignment of static TLS block */

    /* Items from the dynamic section. */
    Elf_Addr *pltgot;		/* PLT or GOT, depending on architecture */
    const Elf_Rel *rel;		/* Relocation entries */
    unsigned long relsize;	/* Size in bytes of relocation info */
    const Elf_Rela *rela;	/* Relocation entries with addend */
    unsigned long relasize;	/* Size in bytes of addend relocation info */
    const Elf_Rel *pltrel;	/* PLT relocation entries */
    unsigned long pltrelsize;	/* Size in bytes of PLT relocation info */
    const Elf_Rela *pltrela;	/* PLT relocation entries with addend */
    unsigned long pltrelasize;	/* Size in bytes of PLT addend reloc info */
    const Elf_Sym *symtab;	/* Symbol table */
    const char *strtab;		/* String table */
    unsigned long strsize;	/* Size in bytes of string table */
#ifdef __mips__
    Elf_Word local_gotno;	/* Number of local GOT entries */
    Elf_Word symtabno;		/* Number of dynamic symbols */
    Elf_Word gotsym;		/* First dynamic symbol in GOT */
#endif

    const Elf_Verneed *verneed; /* Required versions. */
    Elf_Word verneednum;	/* Number of entries in verneed table */
    const Elf_Verdef  *verdef;	/* Provided versions. */
    Elf_Word verdefnum;		/* Number of entries in verdef table */
    const Elf_Versym *versyms;  /* Symbol versions table */

    union
    {
      const Elf32_Word *gnu_buckets;
      const Elf_Hashelt *chains;/* Hash table chain array */
    };
    union
    {
      const Elf32_Word *gnu_chain_zero;
      const Elf_Hashelt *buckets; /* Hash table buckets array */
    };
	
    unsigned long nbuckets;	/* Number of buckets */
    unsigned long nchains;	/* Number of chains */

    Elf32_Word gnu_bitmask_idxbits;
    Elf32_Word gnu_shift;
    const Elf_Addr *gnu_bitmask;

    char *rpath;		/* Search path specified in object */
    Needed_Entry *needed;	/* Shared objects needed by this one (%) */

    STAILQ_HEAD(, Struct_Name_Entry) names; /* List of names for this object we
					       know about. */
    Ver_Entry *vertab;		/* Versions required /defined by this object */
    int vernum;			/* Number of entries in vertab */

    Elf_Addr init;		/* Initialization function to call */
    Elf_Addr fini;		/* Termination function to call */

    bool mainprog : 1;		/* True if this is the main program */
    bool rtld : 1;		/* True if this is the dynamic linker */
    bool textrel : 1;		/* True if there are relocations to text seg */
    bool symbolic : 1;		/* True if generated with "-Bsymbolic" */
    bool bind_now : 1;		/* True if all relocations should be made first */
    bool traced : 1;		/* Already printed in ldd trace output */
    bool jmpslots_done : 1;	/* Already have relocated the jump slots */
    bool init_done : 1;		/* Already have added object to init list */
    bool tls_done : 1;		/* Already allocated offset for static TLS */
    bool phdr_alloc : 1;	/* Phdr is allocated and needs to be freed. */
    bool z_origin : 1;		/* Process rpath and soname tokens */
    bool z_nodelete : 1;	/* Do not unload the object and dependencies */
    bool ref_nodel : 1;		/* Refcount increased to prevent dlclose */
    bool init_scanned: 1;	/* Object is already on init list. */
    bool on_fini_list: 1;	/* Object is already on fini list. */

    struct link_map linkmap;	/* For GDB and dlinfo() */
    Objlist dldags;		/* Object belongs to these dlopened DAGs (%) */
    Objlist dagmembers;		/* DAG has these members (%) */
    dev_t dev;			/* Object's filesystem's device */
    ino_t ino;			/* Object's inode number */
    void *priv;			/* Platform-dependant */
} Obj_Entry;

#define RTLD_MAGIC	0xd550b87a
#define RTLD_VERSION	1

#define RTLD_STATIC_TLS_EXTRA	128

/* Flags to be passed into symlook_ family of functions. */
#define SYMLOOK_IN_PLT	0x01	/* Lookup for PLT symbol */
#define SYMLOOK_DLSYM	0x02	/* Return newes versioned symbol. Used by
				   dlsym. */

/*
 * Symbol cache entry used during relocation to avoid multiple lookups
 * of the same symbol.
 */
typedef struct Struct_SymCache {
    const Elf_Sym *sym;		/* Symbol table entry */
    const Obj_Entry *obj;	/* Shared object which defines it */
} SymCache;

extern void _rtld_error(const char *, ...) __printflike(1, 2);
extern Obj_Entry *map_object(const char *, char *, ssize_t);
extern void *xcalloc(size_t);
extern void *xmalloc(size_t);
extern char *xstrdup(const char *);
extern Elf_Addr _GLOBAL_OFFSET_TABLE_[];

extern void dump_relocations (Obj_Entry *);
extern void dump_obj_relocations (Obj_Entry *);
extern void dump_Elf_Rel (Obj_Entry *, const Elf_Rel *, u_long);
extern void dump_Elf_Rela (Obj_Entry *, const Elf_Rela *, u_long);

/*
 * Function declarations.
 */
unsigned long elf_hash(const char *);
const Elf_Sym *find_symdef(unsigned long, const Obj_Entry *,
  const Obj_Entry **, int, SymCache *);
void init_pltgot(Obj_Entry *);
void lockdflt_init(void);
void obj_free(Obj_Entry *);
Obj_Entry *obj_new(void);
void _rtld_bind_start(void);
const Elf_Sym *symlook_obj(const char *, unsigned long, const Obj_Entry *,
    const Ver_Entry *, int);
void *tls_get_addr_common(Elf_Addr** dtvp, int index, size_t offset);
void *allocate_tls(Obj_Entry *, void *, size_t, size_t);
void free_tls(void *, size_t, size_t);
void *allocate_module_tls(int index);
bool allocate_tls_offset(Obj_Entry *obj);
void free_tls_offset(Obj_Entry *obj);
const Ver_Entry *fetch_ventry(const Obj_Entry *obj, unsigned long);
int open_object(const char *name, unsigned char **, ssize_t *, void *buf);

/*
 * MD function declarations.
 */
int do_copy_relocations(Obj_Entry *);
int reloc_non_plt(Obj_Entry *, Obj_Entry *);
int reloc_plt(Obj_Entry *);
int reloc_jmpslots(Obj_Entry *);
void allocate_initial_tls(Obj_Entry *);

void *rtld_malloc(size_t);
void rtld_free(void *);


#define malloc	rtld_malloc
#define free	rtld_free


#endif /* } */
