#ifndef MACHO_H
#define MACHO_H

#include <stdint.h>
#include "utils.h"

uint32_t kr32(addr_t from);
uint32_t kw32(addr_t to, uint32_t v);
void kread(uint64_t from, void *to, size_t size);

#endif
