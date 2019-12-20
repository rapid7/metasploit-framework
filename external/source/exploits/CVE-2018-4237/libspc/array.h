#ifndef _ARRAY_H_
#define _ARRAY_H_

#include "datatypes.h"

spc_array_t* spc_array_create();

size_t spc_array_get_length(spc_array_t* array);

void spc_array_set_value(spc_array_t* array, size_t index, spc_value_t value);

void spc_array_set_data(spc_array_t* array, size_t index, void* data, size_t length);

#endif
