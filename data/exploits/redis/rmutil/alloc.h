#ifndef __RMUTIL_ALLOC__
#define __RMUTIL_ALLOC__

/* Automatic Redis Module Allocation functions monkey-patching.
 *
 * Including this file while REDIS_MODULE_TARGET is defined, will explicitly
 * override malloc, calloc, realloc & free with RedisModule_Alloc,
 * RedisModule_Callc, etc implementations, that allow Redis better control and
 * reporting over allocations per module.
 *
 * You should include this file in all c files AS THE LAST INCLUDED FILE
 *
 * This only has effect when when compiling with the macro REDIS_MODULE_TARGET
 * defined. The idea is that for unit tests it will not be defined, but for the
 * module build target it will be.
 *
 */

#include <stdlib.h>
#include <redismodule.h>

char *rmalloc_strndup(const char *s, size_t n);

#ifdef REDIS_MODULE_TARGET /* Set this when compiling your code as a module */

#define malloc(size) RedisModule_Alloc(size)
#define calloc(count, size) RedisModule_Calloc(count, size)
#define realloc(ptr, size) RedisModule_Realloc(ptr, size)
#define free(ptr) RedisModule_Free(ptr)

#ifdef strdup
#undef strdup
#endif
#define strdup(ptr) RedisModule_Strdup(ptr)

/* More overriding */
// needed to avoid calling strndup->malloc
#ifdef strndup
#undef strndup
#endif
#define strndup(s, n) rmalloc_strndup(s, n)

#else

#endif /* REDIS_MODULE_TARGET */
/* This function should be called if you are working with malloc-patched code
 * outside of redis, usually for unit tests. Call it once when entering your unit
 * tests' main() */
void RMUTil_InitAlloc();

#endif /* __RMUTIL_ALLOC__ */
