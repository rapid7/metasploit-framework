// PKS, hacky work around 

#ifndef __STDARG_HACK
#define __STDARG_HACK 

#define	va_start(ap, last) __builtin_va_start((ap), (last))
#define	va_arg(ap, type) __builtin_va_arg((ap), type)
#define	va_copy(dest, src) __builtin_va_copy((dest), (src))

/*
 * #if __ISO_C_VISIBLE >= 1999
 * #define	va_copy(dest, src) \
 * __va_copy(dest, src)
 * #endif
 */

#define	va_end(ap) __builtin_va_end(ap)

#define va_list __builtin_va_list

#endif // __STDARG_HACK
