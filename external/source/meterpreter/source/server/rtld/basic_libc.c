// PKS, from libloader.c. __builtin_memcpy doesn't always work :~(

#include <sys/types.h>
#include <signal.h>

#include "linker_debug.h"

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

void *
memset(void *b, int c, size_t len)
{
	char *bb;

	for (bb = (char *)b; len--; )
	  *bb++ = c;
	return (b);
}

// </libloader.c>

void abort()
{
	kill(getpid(), SIGABRT);
	exit(1);
}

char *strcpy(char *dest, const char *src)
{
	do {
		*dest++ = *src++;
	} while(*src != 0);
	*dest++ = 0;
}

int strcmp(const char *s1, const char *s2)
{
	for(; *s1 == *s2; ++s1, ++s2) {
		if(*s1 == 0) return 0;
	}
		
	return *(unsigned char *)s1 - *(unsigned char *)s2;
}
