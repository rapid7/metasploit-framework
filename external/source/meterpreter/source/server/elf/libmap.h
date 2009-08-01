/*
 * $FreeBSD: head/libexec/rtld-elf/libmap.h 141232 2005-02-04 02:46:41Z mdodd $
 */

int	lm_init (char *);
void	lm_fini (void);
char *	lm_find (const char *, const char *);
#ifdef COMPAT_32BIT
char *	lm_findn (const char *, const char *, const int);
#endif
