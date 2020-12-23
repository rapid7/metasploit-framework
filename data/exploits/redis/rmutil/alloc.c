#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "alloc.h"

/* A patched implementation of strdup that will use our patched calloc */
char *rmalloc_strndup(const char *s, size_t n) {
  char *ret = calloc(n + 1, sizeof(char));
  if (ret)
    memcpy(ret, s, n);
  return ret;
}

/*
 * Re-patching RedisModule_Alloc and friends to the original malloc functions
 *
 * This function should be called if you are working with malloc-patched code
 * outside of redis, usually for unit tests. Call it once when entering your unit
 * tests' main().
 *
 * Since including "alloc.h" while defining REDIS_MODULE_TARGET
 * replaces all malloc functions in redis with the RM_Alloc family of functions,
 * when running that code outside of redis, your app will crash. This function
 * patches the RM_Alloc functions back to the original mallocs. */
void RMUTil_InitAlloc() {

  RedisModule_Alloc = malloc;
  RedisModule_Realloc = realloc;
  RedisModule_Calloc = calloc;
  RedisModule_Free = free;
  RedisModule_Strdup = strdup;
}
