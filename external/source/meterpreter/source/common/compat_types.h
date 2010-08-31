#ifndef	UNIX_COMPAT_TYPES_H
#define	UNIX_COMPAT_TYPES_H
#include <sys/errno.h>
#include <sys/types.h>
#include <netinet/in.h>

#if defined(__FreeBSD__) 
#include <sys/filio.h>
#elif defined(__linux__)
#define __va_list  __ptr_t
#define __USE_XOPEN
#else
#error unknown OS
#endif

#define NULL	((void *)0)

#define	PAGE_SIZE	4096
#define PAGE_SHIFT	12


/*
 * need to separate out platform types
 */

#if defined(__FreeBSD__)
#if defined(__LP64__)
typedef	int64_t		intptr_t;
typedef	uint64_t	uintptr_t;
typedef	uint64_t	uintmax_t;
#else
typedef	int32_t		intptr_t;
typedef	uint32_t	uintptr_t;
typedef	uint32_t	uintmax_t;
#endif
#endif

#define	PAGE_MASK	(PAGE_SIZE-1)
#define trunc_page(x)   ((unsigned long)(x) & ~(PAGE_MASK))


/*
 * Protections are chosen from these bits, or-ed together
 */
#define PROT_NONE       0x00    /* no permissions */
#define PROT_READ       0x01    /* pages can be read */
#define PROT_WRITE      0x02    /* pages can be written */
#define PROT_EXEC       0x04    /* pages can be executed */

/*
 * Flags contain sharing type and options.
 * Sharing types; choose one.
 */
#define MAP_SHARED      0x0001          /* share changes */
#define MAP_PRIVATE     0x0002          /* changes are private */

/*
 * Mapping type
 */
#define MAP_FILE         0x0000 /* map from file (default) */
#define MAP_ANON         0x1000 /* allocated from memory, swap space */

/*
 * Error return from mmap()
 */
#define MAP_FAILED      ((void *)-1)

/*
 * Advice to madvise
 */
#define _MADV_NORMAL    0       /* no further special treatment */
#define _MADV_RANDOM    1       /* expect random page references */
#define _MADV_SEQUENTIAL 2      /* expect sequential page references */
#define _MADV_WILLNEED  3       /* will need these pages */
#define _MADV_DONTNEED  4       /* dont need these pages */

#define MADV_NORMAL     _MADV_NORMAL
#define MADV_RANDOM     _MADV_RANDOM
#define MADV_SEQUENTIAL _MADV_SEQUENTIAL
#define MADV_WILLNEED   _MADV_WILLNEED
#define MADV_DONTNEED   _MADV_DONTNEED
#define MADV_FREE       5       /* dont need these pages, and junk contents */





void *memcpy(void *idst, const void *isrc, size_t n);

int strcmp (const char *s1, const char *s2);

int strncmp(const char *s1, const char *s2, size_t n);

size_t strlen (const char *s);

char *strcpy (char *dst, const char *src);

char *strcat (char *dst, const char *src);

char *strstr(const char *s, const char *find);

unsigned long s_strtoul (const char *cp);

void *memset(void *b, int c, size_t len);

void bzero(void *b, size_t len);

char	*strdup(const char *__restrict);

#define	_strdup				strdup
#define	_vsnprintf			vsnprintf
#define	strcat_s(buf1, len, buf2)	strcat((buf1), (buf2))
#define	closesocket			close

#define	STDIN_FILENO    0       /* standard input file descriptor */
#define	STDOUT_FILENO   1       /* standard output file descriptor */
#define STDERR_FILENO   2       /* standard error file descriptor */



ssize_t write(int d, const void *buf, size_t nbytes);
ssize_t read(int d, void *buf, size_t nbytes);


void	abort(void);

void  free(void *ptr);

void *malloc(size_t size);


#ifdef __GNUCLIKE_BUILTIN_STDARG

#ifndef va_start
#define va_start(ap, last) \
	__builtin_va_start((ap), (last))
#endif

#ifndef va_arg
#define va_arg(ap, type) \
	__builtin_va_arg((ap), type)
#endif

#ifndef __va_copy
#define __va_copy(dest, src) \
	__builtin_va_copy((dest), (src))
#endif

#if __ISO_C_VISIBLE >= 1999
#ifndef va_copy
#define va_copy(dest, src) \
	__va_copy(dest, src)
#endif
#endif

#ifndef va_end
#define va_end(ap) \
	__builtin_va_end(ap)
#endif

#endif


typedef	char		BOOL;
typedef	char		BOOLEAN;
typedef	BOOL *		LPBOOL;
typedef	char		CHAR;
typedef	CHAR *		PCHAR;
typedef	void *		LPVOID;
typedef	char		BYTE;


typedef	uint32_t	ULONG;
typedef	uint32_t *	PULONG;
typedef	const char	CSTR;
typedef	unsigned char	UCHAR;
typedef UCHAR *		PUCHAR;
typedef	CSTR *		LPCSTR;
typedef	char *		LPSTR;
typedef	long		DWORD;
typedef	DWORD *		LPDWORD;
typedef	int32_t		LONG;
typedef	LONG *		LPLONG;
typedef	unsigned int	UINT;
typedef	int		HANDLE;
typedef	int		SOCKET;
typedef	void		VOID;
typedef	VOID *		PVOID;
typedef	void *		HMODULE;
typedef	short		SHORT;
typedef unsigned short  USHORT;

#ifndef TRUE
 #define TRUE (1)
#endif
#ifndef FALSE
 #define FALSE (0)
#endif

#define ERROR_NOT_FOUND		ENOENT
#define ERROR_NOT_ENOUGH_MEMORY	ENOMEM
#define ERROR_INVALID_PARAMETER	EINVAL
#define ERROR_INVALID_HANDLE   	EINVAL
#define ERROR_INVALID_DATA     	EINVAL
#define ERROR_UNSUPPORTED_COMPRESSION	EINVAL
#define	ERROR_NOT_SUPPORTED	EOPNOTSUPP

#if defined(__FreeBSD__)
 #define	ERROR_INSTALL_USEREXIT	EPROGUNAVAIL
#elif defined(__linux__)
 #define	ERROR_INSTALL_USEREXIT	ENOPROTOOPT
#else
 #error unknown OS
#endif

#define	ERROR_SUCCESS		(0)
#define	NO_ERROR		(0)

#ifndef __WIN32__
 #define INVALID_HANDLE_VALUE    (0)
 #define WSAEWOULDBLOCK          EWOULDBLOCK

/* SOCKET */
 #define SOCKET_ERROR (-1)
 #define INVALID_SOCKET (-1)
#endif /* __WIN32__  */

int local_error;

#define	GetLastError()		(local_error != -1 ? local_error : errno)
#define	SetLastError(x)		(local_error = (x))
#define	__declspec(x) 

#define	__try
#define	__except(x)	if (0)

#endif
