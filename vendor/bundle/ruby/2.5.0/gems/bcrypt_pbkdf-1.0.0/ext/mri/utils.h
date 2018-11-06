#include <stdlib.h>
#include <stddef.h>

void explicit_bzero(void *p, size_t n);
#define sodium_memzero explicit_bzero