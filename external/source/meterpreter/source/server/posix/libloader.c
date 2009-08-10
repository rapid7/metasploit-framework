#include <sys/types.h>

#ifdef __linux__
#include "sfsyscall.h"
#endif
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/mman.h>


#define NULL	((void *)0)

/*
 * Forget about sparc / alpha / ia64 for now 
 */ 
#define	PAGE_SIZE	4096
#define PAGE_MASK	(PAGE_SIZE-1)
#define round_page(x)           (((x) + PAGE_MASK) & ~PAGE_MASK)

#include "rtld.h"
#include "zlib/zlib.h"

void *
memcpy(void *idst, const void *isrc, size_t n)
{
	char *ret = idst;
	char *dst = idst;
	const char *src = isrc;
	
	while (n--)
		*dst++ = *src++;
	return ret;
}

static int
strncmp(const char *s1, const char *s2, size_t n)
{

	if (n == 0)
		return (0);
	do {
		if (*s1 != *s2++)
			return (*(const unsigned char *)s1 -
				*(const unsigned char *)(s2 - 1));
		if (*s1++ == 0)
			break;
	} while (--n != 0);
	return (0);
}

size_t
strlen(str)
	const char *str;
{
	register const char *s;

	for (s = str; *s; ++s);
	return(s - str);
}

static char *
strstr(const char *s, const char *find)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != 0) {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return (NULL);
			} while (sc != c);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)(unsigned long)s);
}

void *
memset(void *b, int c, size_t len)
{
	char *bb;

	for (bb = (char *)b; len--; )
	  *bb++ = c;
	return (b);
}


int
_sigfillset(set)
	sigset_t *set;
{
	int i;

	for (i = 0; i < _SIG_WORDS; i++)
		set->__bits[i] = ~0U;
	return (0);
}

int
_sigdelset(set, signo)
	sigset_t *set;
	int signo;
{

	if (signo <= 0 || signo > _SIG_MAXSIG) {
		errno = EINVAL;
		return (-1);
	}
	set->__bits[_SIG_WORD(signo)] &= ~_SIG_BIT(signo);
	return (0);
}

/* eof libc functions */

typedef struct handle_s
{
	char *mem_base;   /* base address of maped *.so */
	unsigned long *hash_tab;  /* hash table */
	char *dyn_str_tab;    /* dyn_name table */
	Elf_Sym *dyn_sym_tab; /* dynamic symbol table */
	Elf_Rel *plt_rel;   /* PLT relocation table */
	Elf_Rel *dyn_rel;   /*  relocation table */
} handle_t;


static handle_t libc_handle;
static char *sym;
static unsigned long addr;

#define MLOCK_MAX_SIZE 31744

#ifdef __linux__
#define MAP_FLAGS  MAP_ANONYMOUS
#else
#define MAP_FLAGS  MAP_ANON|MAP_NOCORE
#endif


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


#include "metsrv_main.h"
#include "libcrypto_so.h"
#include "libssl_so.h"
#include "libuc_so.h"

typedef struct library_object {
	void *lo_ptr;
} lobj_t;

typedef struct library_info {
	unsigned int 	l_output_size;
	unsigned int 	l_input_size;
	char 		*l_name;	
	unsigned char	*l_data;
	unsigned char	*l_data_uncompressed;	
	lobj_t		*l_obj;
} linfo_t;

lobj_t metsrv_main_obj;
lobj_t libcrypto_so_obj;
lobj_t libssl_so_obj;
lobj_t libuc_so_obj;

/*
 * The user must make sure that the list of library names matches those
 * in metsrv's symbol table (see elf headers as ldd often gets confused)
 */
static linfo_t startlibs[] = {
	{metsrv_main_size, metsrv_main_length, "meta server", metsrv_main, NULL, &metsrv_main_obj},
	{libcrypto_so_size, libcrypto_so_length, "libcrypto.so", libcrypto_so, NULL, &libcrypto_so_obj},
	{libssl_so_size, libssl_so_length, "libssl.so", libssl_so, NULL, &libssl_so_obj},
	{libuc_so_size, libuc_so_length, "libc.so", libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libuc.so", libuc_so, NULL, &libuc_so_obj},
	
	{libuc_so_size, libuc_so_length, "libdl.so", libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libz.so",  libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libgssapi_krb5.so", libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libkrb5.so", libuc_so, NULL, &libuc_so_obj}, 
	{libuc_so_size, libuc_so_length, "libcom_err.so", libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libk5crypto.so", libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libresolv.so", libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libkeyutils.so", libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libselinux.so", libuc_so, NULL, &libuc_so_obj},
	{libuc_so_size, libuc_so_length, "libsepol.so", libuc_so, NULL, &libuc_so_obj},
	{0, 0, NULL, NULL, NULL, NULL},
};

static void *
zalloc(void *opaque, unsigned int count, unsigned int size)
{

	return (malloc(count*size));
}

static void
zfree(void *opaque, void *addr)
{

	free(addr);
}

static void *
dumb_malloc(int size)
{

	return mmap (0, size, PROT_WRITE | PROT_READ,
	    MAP_PRIVATE | MAP_FLAGS, -1, 0);
}



typedef void (*func_ptr_type)();
Obj_Entry *entry_start;
func_ptr_type exit_func;

func_ptr_type
_rtld_late(unsigned char *base, unsigned char *buf, ssize_t size,
    func_ptr_type *exit_proc, Obj_Entry **objp);


int
open_object(const char *name, unsigned char **buf, ssize_t *size,
	void *obj)
{
	linfo_t *lib;

	for (lib = startlibs; lib->l_input_size != 0; lib++)	
		if (strstr(name, lib->l_name) != NULL) {
			if (lib->l_obj->lo_ptr == NULL) {
				*buf = lib->l_data_uncompressed;
				*size = lib->l_output_size;
			} else
				*(uintptr_t *)obj = (uintptr_t)lib->l_obj->lo_ptr;
			return (0);
		}
	return (1);
}

void
set_object(const char *name, void *obj)
{
	linfo_t *lib;

	for (lib = startlibs; lib->l_input_size != 0; lib++)	
		if (strstr(name, lib->l_name) != NULL) {
			lib->l_obj->lo_ptr = obj;
			break;
		}
}


#ifdef __i386__
void (*_late_start)(int, char **, ...);
#else	
void (*_late_start)(char **ap, void (*cleanup)(void));
#endif

void call_late_start(void *, int argc, ...);

#if 0
void
call_late_start(int argc, char **argv, char **environ)
{
        __asm__("movl %0, %%edx" : "=rm"(exit_func));
	__asm__("jmp %0", : "=rm"(_late_start));
	printf("calling late start with argv argc=%d argv=%p &argv[0]==%p\n",
	    argc, argv, &argv[0]);
	_late_start(argc, argv[0], argv[1], NULL, environ, NULL);
	
}
#endif
void
metsrv_rtld(int fd, void *base)
{
	z_stream stream;
	int i, status, size;
	linfo_t *lib;
	char *self, *inflate_buffer;
	char *newenviron[] = {"USER=me"};
	char *ap[4];
	char *argv[] = {"metserv_main", (char *)fd, NULL};

	
	printf("fd=%d ap=%p \n", fd, ap);
	ap[0] = (char *)2;
	ap[1] = "metsrv_main";
	ap[2] = (char *) fd;	
	ap[3] = (char *)newenviron;

	memset(&stream, 0, sizeof(stream));
	stream.zalloc = zalloc;
	stream.zfree = zfree;

	for (lib = startlibs; lib->l_input_size != 0; lib++) {
		int input_size  = lib->l_input_size;
		unsigned char *input_buffer = lib->l_data;

		if (check_header(&input_buffer, &input_size) != Z_OK) {
			inflate_buffer = lib->l_data;		
			goto uncompressed;
		}

		/* windowBits is passed < 0 to tell that there is no zlib header.
		 * Note that in this case inflate *requires* an extra "dummy" byte
		 * after the compressed stream in order to complete decompression and
		 * return Z_STREAM_END. Here the gzip CRC32 ensures that 4 bytes are
		 * present after the compressed stream.
		 */
		inflateInit2(&stream, -MAX_WBITS);
		inflate_buffer = dumb_malloc(lib->l_output_size);
		
		stream.avail_in = input_size;
		stream.next_in = input_buffer;
		stream.avail_out = lib->l_output_size;
		stream.next_out = inflate_buffer;
		status = inflate(&stream, Z_FINISH);
		if (status != Z_STREAM_END) {
			/* XXX error */
			exit(1);

		}
	uncompressed:
		lib->l_data_uncompressed = inflate_buffer;
	}

	self = startlibs[0].l_data_uncompressed;
	size = startlibs[0].l_output_size;

	_late_start = (void*) _rtld_late(base, self, size, &exit_func, &entry_start);

#ifdef __i386__
	call_late_start(_late_start, 2, ap[1], ap[2], NULL, NULL);
#else
	_late_start(&ap[0], exit_func);
#endif
}

