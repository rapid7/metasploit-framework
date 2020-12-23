#include "datatypes.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>

spc_array_t* spc_array_create()
{
    return calloc(sizeof(spc_array_t), 1);
}

void spc_array_destroy(spc_array_t* array)
{
    for (size_t i = 0; i < array->length; i++)
        spc_value_destroy(array->values[i]);

    free(array->values);
    free(array);
}

size_t spc_array_get_length(spc_array_t* array)
{
    return array->length;
}

static void resize_array(spc_array_t* array, size_t length)
{
    if (array->length >= length)
        return;

    size_t prev_length = array->length;

    if (array->capacity < length) {
        array->capacity *= 2;
        if (array->capacity == 0)
            array->capacity = 4;        // initial capacity
        array->values = realloc(array->values, array->capacity * sizeof(spc_value_t));
        ASSERT(array->values);
    }

    array->length = length;

    // Null initialize
    for (size_t i = prev_length; i < length; i++)
        array->values[i].type = SPC_TYPE_NULL;
}

void spc_array_set_value(spc_array_t* array, size_t index, spc_value_t value)
{
    if (index >= array->length)
        resize_array(array, index + 1);

    array->values[index] = value;
}

void spc_array_set_data(spc_array_t* array, size_t index, void* data, size_t length)
{
    void* buf = malloc(length);
    memcpy(buf, data, length);

    spc_value_t value;
    value.type = SPC_TYPE_DATA;
    value.value.data.ptr = buf;
    value.value.data.size = length;

    spc_array_set_value(array, index, value);
}

spc_value_t spc_array_get_value(spc_array_t* array, size_t index)
{
    if (index < array->length)
        return array->values[index];
    return spc_null_create();
}
