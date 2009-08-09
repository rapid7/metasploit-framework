#include "compat_types.h"
#include <sys/syscall.h>

int __use_xprintf = -1;

int
utrace(const void *addr, size_t len)
{
	/* XXX no-op */
	return (0);
}

void
bzero(void *b, size_t len)
{
	
	(void)memset(b, 0, len);
}

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

int
strcmp (const char *s1, const char *s2)
{
	while (*s1 == *s2++)
		if (*s1++ == 0)
			return (0);
	return (*(const unsigned char *)s1 - *(const unsigned char *)(s2 - 1));
}

int
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
strlen (const char *s)
{
	const char *p;

	for (p = s; *p; ++p);
	return (p - s);
}

char *
strcpy (char *dst, const char *src)
{
	char *ret = dst;

	while ((*dst++ = *src++) != '\0');
	return ret;
}

char *
strcat (char *dst, const char *src)
{
	char *ret = dst;

	while (*dst++ != '\0');
	--dst;
	while ((*dst++ = *src++) != '\0');
	return ret;
}

char *
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

#define isdigit(c) ({ int __c = (c); __c >= '0' && __c <= '9'; })

unsigned long
s_strtoul (const char *cp)
{
	unsigned long result = 0, value;

	cp += 2;
	while ((value = isdigit (*cp) ? *cp - '0' : *cp - 'a' + 10) < 16)
	{
		result = result * 16 + value;
		cp++;
	}
	return result;
}

void *
memset(void *b, int c, size_t len)
{
	char *bb;

	if (c == 0)
		bzero(b, len);
	else
		for (bb = (char *)b; len--; )
			*bb++ = c;
	return (b);
}


char *
strdup(const char *string)
{
	size_t len;
	char *copy;

	len = strlen(string) + 1;
	copy = malloc(len);
	memcpy(copy, string, len);
	return (copy);
}

#define RAND_MAX        0x7fffffff

static int
do_rand(unsigned long *ctx)
{

#ifdef  USE_WEAK_SEEDING
	/*
	 * Historic implementation compatibility.
	 * The random sequences do not vary much with the seed,
	 * even with overflowing.
	 */
	return ((*ctx = *ctx * 1103515245 + 12345) % ((u_long)RAND_MAX + 1));

#else   /* !USE_WEAK_SEEDING */
	/*
	 * Compute x = (7^5 * x) mod (2^31 - 1)
	 * without overflowing 31 bits:
	 *      (2^31 - 1) = 127773 * (7^5) + 2836
	 * From "Random number generators: good ones are hard to find",
	 * Park and Miller, Communications of the ACM, vol. 31, no. 10,
	 * October 1988, p. 1195.
	 */
	long hi, lo, x;

	/* Can't be initialized with 0, so use another value. */
	if (*ctx == 0)
		*ctx = 123459876;
	hi = *ctx / 127773;
	lo = *ctx % 127773;
	x = 16807 * lo - 2836 * hi;
	if (x < 0)
		x += 0x7fffffff;

	return ((*ctx = x) % ((unsigned long)RAND_MAX + 1));
#endif  /* !USE_WEAK_SEEDING */
}
static unsigned long next = 1;

int
rand(void)
{
	return (do_rand(&next));
}

void
srand(unsigned int seed)
{
	next = seed;
}


#ifndef __linux__
/* XXXX UNIMPLEMENTED*/
void
abort(void)
{
	/* XXXX implement me */
	exit(1);
}	

int
vsnprintf(char * __restrict str, size_t n, const char * __restrict fmt,
    __va_list ap)
{

	return (0);
}

int
vsnprintf_s(char * __restrict str, size_t n, size_t n2, const char * __restrict fmt,
    __va_list ap)
{

	return (0);
}

#endif
#pragma weak __stack_chk_guard
void
__stack_chk_guard(void)
{

}


/* eof libc functions */

ssize_t
recv(int s, void *buf, size_t len, int flags)
{

	return read(s, buf, len);
}

#ifdef __linux__
void
__libc_csu_init(void)
{

}

void
__libc_csu_fini(void)
{

}


void
__gmon_start__(void)
{

}

#undef errno
int errno;

#pragma weak __errno_location
int *
__errno_location (void)
{

	return &errno;
}


void
__libc_start_main(int (*main_func)(int, char **, char **),
	int argc, char **argv, char **environ)
{

	printf("start_main main=%p argc=%x argv=%p\n", main_func, argc, argv);
	
	exit(main_func(argc, argv, environ));
}

#else

#pragma weak _init_tls
void
_init_tls(void)
{

}

#endif







