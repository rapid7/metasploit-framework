#include <stdlib.h>

#include "datatypes.h"

const spc_port_t SPC_NULL_PORT = {.name = MACH_PORT_NULL, .type = 0};

spc_value_t spc_null_create()
{
    spc_value_t null = { .type = SPC_TYPE_NULL };
    return null;
}

void spc_value_destroy(spc_value_t value)
{
    switch (value.type) {
        case SPC_TYPE_STRING:
            free(value.value.str);
            break;
        case SPC_TYPE_UUID:
            free(value.value.ptr);
            break;
        case SPC_TYPE_DATA:
            free(value.value.data.ptr);
            break;
        case SPC_TYPE_ARRAY:
            spc_array_destroy(value.value.array);
            break;
        case SPC_TYPE_DICT:
            spc_dictionary_destroy(value.value.dict);
            break;
        case SPC_TYPE_SEND_PORT:
        case SPC_TYPE_RECV_PORT:
        case SPC_TYPE_FD:
            mach_port_deallocate(mach_task_self(), value.value.port.name);
            break;
    }
}

void spc_message_destroy(spc_message_t* msg)
{
    spc_dictionary_destroy(msg->content);
    free(msg);
}
