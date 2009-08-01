/*-
 * Copyright 1996, 1997, 1998, 1999 John D. Polstra.
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
 * $FreeBSD: head/libexec/rtld-elf/amd64/reloc.c 157198 2006-03-28 06:09:24Z davidxu $
 */

/*
 * Dynamic linker for ELF.
 *
 * John Polstra <jdp@polstra.com>.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <machine/sysarch.h>

#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "rtld.h"

/*
 * Process the special R_X86_64_COPY relocations in the main program.  These
 * copy data from a shared object into a region in the main program's BSS
 * segment.
 *
 * Returns 0 on success, -1 on failure.
 */
int
do_copy_relocations(Obj_Entry *dstobj)
{
    const Elf_Rela *relalim;
    const Elf_Rela *rela;

    assert(dstobj->mainprog);	/* COPY relocations are invalid elsewhere */

    relalim = (const Elf_Rela *) ((caddr_t) dstobj->rela + dstobj->relasize);
    for (rela = dstobj->rela;  rela < relalim;  rela++) {
	if (ELF_R_TYPE(rela->r_info) == R_X86_64_COPY) {
	    void *dstaddr;
	    const Elf_Sym *dstsym;
	    const char *name;
	    unsigned long hash;
	    size_t size;
	    const void *srcaddr;
	    const Elf_Sym *srcsym;
	    Obj_Entry *srcobj;
	    const Ver_Entry *ve;

	    dstaddr = (void *) (dstobj->relocbase + rela->r_offset);
	    dstsym = dstobj->symtab + ELF_R_SYM(rela->r_info);
	    name = dstobj->strtab + dstsym->st_name;
	    hash = elf_hash(name);
	    size = dstsym->st_size;
	    ve = fetch_ventry(dstobj, ELF_R_SYM(rela->r_info));

	    for (srcobj = dstobj->next;  srcobj != NULL;  srcobj = srcobj->next)
		if ((srcsym = symlook_obj(name, hash, srcobj, ve, 0)) != NULL)
		    break;

	    if (srcobj == NULL) {
		_rtld_error("Undefined symbol \"%s\" referenced from COPY"
		  " relocation in %s", name, dstobj->path);
		return -1;
	    }

	    srcaddr = (const void *) (srcobj->relocbase + srcsym->st_value);
	    memcpy(dstaddr, srcaddr, size);
	}
    }

    return 0;
}

/* Initialize the special GOT entries. */
void
init_pltgot(Obj_Entry *obj)
{
    if (obj->pltgot != NULL) {
	obj->pltgot[1] = (Elf_Addr) obj;
	obj->pltgot[2] = (Elf_Addr) &_rtld_bind_start;
    }
}

/* Process the non-PLT relocations. */
int
reloc_non_plt(Obj_Entry *obj, Obj_Entry *obj_rtld)
{
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
	SymCache *cache;
	int bytes = obj->nchains * sizeof(SymCache);
	int r = -1;

	/*
	 * The dynamic loader may be called from a thread, we have
	 * limited amounts of stack available so we cannot use alloca().
	 */
	cache = mmap(NULL, bytes, PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
	if (cache == MAP_FAILED)
	    cache = NULL;

	relalim = (const Elf_Rela *) ((caddr_t) obj->rela + obj->relasize);
	for (rela = obj->rela;  rela < relalim;  rela++) {
	    Elf_Addr *where = (Elf_Addr *) (obj->relocbase + rela->r_offset);
	    Elf32_Addr *where32 = (Elf32_Addr *)where;

	    switch (ELF_R_TYPE(rela->r_info)) {

	    case R_X86_64_NONE:
		break;

	    case R_X86_64_64:
		{
		    const Elf_Sym *def;
		    const Obj_Entry *defobj;

		    def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
		      false, cache);
		    if (def == NULL)
			goto done;

		    *where = (Elf_Addr) (defobj->relocbase + def->st_value + rela->r_addend);
		}
		break;

	    case R_X86_64_PC32:
		/*
		 * I don't think the dynamic linker should ever see this
		 * type of relocation.  But the binutils-2.6 tools sometimes
		 * generate it.
		 */
		{
		    const Elf_Sym *def;
		    const Obj_Entry *defobj;

		    def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
		      false, cache);
		    if (def == NULL)
			goto done;

		    *where32 = (Elf32_Addr) (unsigned long) (defobj->relocbase +
		        def->st_value + rela->r_addend - (Elf_Addr) where);
		}
		break;
	/* missing: R_X86_64_GOT32 R_X86_64_PLT32 */

	    case R_X86_64_COPY:
		/*
		 * These are deferred until all other relocations have
		 * been done.  All we do here is make sure that the COPY
		 * relocation is not in a shared library.  They are allowed
		 * only in executable files.
		 */
		if (!obj->mainprog) {
		    _rtld_error("%s: Unexpected R_X86_64_COPY relocation"
		      " in shared library", obj->path);
		    goto done;
		}
		break;

	    case R_X86_64_GLOB_DAT:
		{
		    const Elf_Sym *def;
		    const Obj_Entry *defobj;

		    def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
		      false, cache);
		    if (def == NULL)
			goto done;

		    *where = (Elf_Addr) (defobj->relocbase + def->st_value);
		}
		break;

	    case R_X86_64_TPOFF64:
		{
		    const Elf_Sym *def;
		    const Obj_Entry *defobj;

		    def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
		      false, cache);
		    if (def == NULL)
			goto done;

		    /*
		     * We lazily allocate offsets for static TLS as we
		     * see the first relocation that references the
		     * TLS block. This allows us to support (small
		     * amounts of) static TLS in dynamically loaded
		     * modules. If we run out of space, we generate an
		     * error.
		     */
		    if (!defobj->tls_done) {
			if (!allocate_tls_offset((Obj_Entry*) defobj)) {
			    _rtld_error("%s: No space available for static "
					"Thread Local Storage", obj->path);
			    goto done;
			}
		    }

		    *where = (Elf_Addr) (def->st_value - defobj->tlsoffset +
					 rela->r_addend);
		}
		break;

	    case R_X86_64_TPOFF32:
		{
		    const Elf_Sym *def;
		    const Obj_Entry *defobj;

		    def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
		      false, cache);
		    if (def == NULL)
			goto done;

		    /*
		     * We lazily allocate offsets for static TLS as we
		     * see the first relocation that references the
		     * TLS block. This allows us to support (small
		     * amounts of) static TLS in dynamically loaded
		     * modules. If we run out of space, we generate an
		     * error.
		     */
		    if (!defobj->tls_done) {
			if (!allocate_tls_offset((Obj_Entry*) defobj)) {
			    _rtld_error("%s: No space available for static "
					"Thread Local Storage", obj->path);
			    goto done;
			}
		    }

		    *where32 = (Elf32_Addr) (def->st_value -
					     defobj->tlsoffset +
					     rela->r_addend);
		}
		break;

	    case R_X86_64_DTPMOD64:
		{
		    const Elf_Sym *def;
		    const Obj_Entry *defobj;

		    def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
		      false, cache);
		    if (def == NULL)
			goto done;

		    *where += (Elf_Addr) defobj->tlsindex;
		}
		break;

	    case R_X86_64_DTPOFF64:
		{
		    const Elf_Sym *def;
		    const Obj_Entry *defobj;

		    def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
		      false, cache);
		    if (def == NULL)
			goto done;

		    *where += (Elf_Addr) (def->st_value + rela->r_addend);
		}
		break;

	    case R_X86_64_DTPOFF32:
		{
		    const Elf_Sym *def;
		    const Obj_Entry *defobj;

		    def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
		      false, cache);
		    if (def == NULL)
			goto done;

		    *where32 += (Elf32_Addr) (def->st_value + rela->r_addend);
		}
		break;

	    case R_X86_64_RELATIVE:
		*where = (Elf_Addr)(obj->relocbase + rela->r_addend);
		break;

	/* missing: R_X86_64_GOTPCREL, R_X86_64_32, R_X86_64_32S, R_X86_64_16, R_X86_64_PC16, R_X86_64_8, R_X86_64_PC8 */

	    default:
		_rtld_error("%s: Unsupported relocation type %u"
		  " in non-PLT relocations\n", obj->path,
		  (unsigned int)ELF_R_TYPE(rela->r_info));
		goto done;
	    }
	}
	r = 0;
done:
	if (cache)
	    munmap(cache, bytes);
	return(r);
}

/* Process the PLT relocations. */
int
reloc_plt(Obj_Entry *obj)
{
    const Elf_Rela *relalim;
    const Elf_Rela *rela;

    relalim = (const Elf_Rela *)((char *)obj->pltrela + obj->pltrelasize);
    for (rela = obj->pltrela;  rela < relalim;  rela++) {
	Elf_Addr *where;

	assert(ELF_R_TYPE(rela->r_info) == R_X86_64_JMP_SLOT);

	/* Relocate the GOT slot pointing into the PLT. */
	where = (Elf_Addr *)(obj->relocbase + rela->r_offset);
	*where += (Elf_Addr)obj->relocbase;
    }
    return 0;
}

/* Relocate the jump slots in an object. */
int
reloc_jmpslots(Obj_Entry *obj)
{
    const Elf_Rela *relalim;
    const Elf_Rela *rela;

    if (obj->jmpslots_done)
	return 0;
    relalim = (const Elf_Rela *)((char *)obj->pltrela + obj->pltrelasize);
    for (rela = obj->pltrela;  rela < relalim;  rela++) {
	Elf_Addr *where, target;
	const Elf_Sym *def;
	const Obj_Entry *defobj;

	assert(ELF_R_TYPE(rela->r_info) == R_X86_64_JMP_SLOT);
	where = (Elf_Addr *)(obj->relocbase + rela->r_offset);
	def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj, true, NULL);
	if (def == NULL)
	    return -1;
	target = (Elf_Addr)(defobj->relocbase + def->st_value + rela->r_addend);
	reloc_jmpslot(where, target, defobj, obj, (const Elf_Rel *)rela);
    }
    obj->jmpslots_done = true;
    return 0;
}

void
allocate_initial_tls(Obj_Entry *objs)
{
    /*
     * Fix the size of the static TLS block by using the maximum
     * offset allocated so far and adding a bit for dynamic modules to
     * use.
     */
    tls_static_space = tls_last_offset + RTLD_STATIC_TLS_EXTRA;
    amd64_set_fsbase(allocate_tls(objs, 0,
				  3*sizeof(Elf_Addr), sizeof(Elf_Addr)));
}

void *__tls_get_addr(tls_index *ti)
{
    Elf_Addr** segbase;
    Elf_Addr* dtv;

    __asm __volatile("movq %%fs:0, %0" : "=r" (segbase));
    dtv = segbase[1];

    return tls_get_addr_common(&segbase[1], ti->ti_module, ti->ti_offset);
}
