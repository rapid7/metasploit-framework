#include "datatypes.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>

extern int fileport_makeport(int fd, mach_port_t* port);

spc_dictionary_t* spc_dictionary_create()
{
    return calloc(sizeof(spc_dictionary_t), 1);
}

void spc_dictionary_destroy(spc_dictionary_t* dict)
{
    spc_dictionary_item_t* current, *last;
    current = dict->items;
    while (current) {
        free(current->key);

        spc_value_destroy(current->value);

        last = current;
        current = current->next;
        free(last);
    }

    free(dict);
}

spc_dictionary_item_t* spc_dictionary_lookup(spc_dictionary_t* dict, const char* key)
{
    spc_dictionary_item_t* current = dict->items;
    while (current) {
        if (strcmp(current->key, key) == 0)
            return current;

        current = current->next;
    }

    return NULL;
}

spc_dictionary_item_t* spc_dictionary_add_item(spc_dictionary_t* dict, const char* key, uint32_t type)
{
    spc_dictionary_item_t* item = spc_dictionary_lookup(dict, key);
    if (item) {
        spc_value_destroy(item->value);
    } else {
        item = malloc(sizeof(spc_dictionary_item_t));
        item->next = dict->items;
        dict->items = item;
        dict->num_items++;
        item->key = strdup(key);
    }
    item->value.type = type;
    return item;
}

void spc_dictionary_set_value(spc_dictionary_t* dict, const char* key, spc_value_t value)
{
    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_STRING);
    item->value = value;
}

void spc_dictionary_set_string(spc_dictionary_t* dict, const char* key, const char* value)
{
    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_STRING);
    item->value.value.str = strdup(value);
}

void spc_dictionary_set_uint64(spc_dictionary_t* dict, const char* key, uint64_t value)
{
    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_UINT64);
    item->value.value.u64 = value;
}

void spc_dictionary_set_int64(spc_dictionary_t* dict, const char* key, int64_t value)
{
    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_INT64);
    item->value.value.i64 = value;
}

void spc_dictionary_set_data(spc_dictionary_t* dict, const char* key, const void* bytes, size_t len)
{
    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_DATA);
    void* buf = malloc(len);
    memcpy(buf, bytes, len);
    item->value.value.data.ptr = buf;
    item->value.value.data.size = len;
}

void spc_dictionary_set_fd(spc_dictionary_t* dict, const char* key, int fd)
{
    mach_port_t fileport;
    fileport_makeport(fd, &fileport);

    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_FD);
    item->value.value.port.name = fileport;
    item->value.value.port.type = MACH_MSG_TYPE_COPY_SEND;
}

// TODO make port type a parameter
void spc_dictionary_set_send_port(spc_dictionary_t* dict, const char* key, mach_port_t port)
{
    mach_port_addref(port, MACH_PORT_RIGHT_SEND);

    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_SEND_PORT);
    item->value.value.port.name = port;
    item->value.value.port.type = MACH_MSG_TYPE_COPY_SEND;
}

void spc_dictionary_set_receive_port(spc_dictionary_t* dict, const char* key, mach_port_t port)
{
    mach_port_addref(port, MACH_PORT_RIGHT_RECEIVE);

    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_RECV_PORT);
    item->value.value.port.name = port;
    item->value.value.port.type = MACH_MSG_TYPE_MOVE_RECEIVE;
}

void spc_dictionary_set_bool(spc_dictionary_t* dict, const char* key, int value)
{
    spc_dictionary_item_t* item = spc_dictionary_add_item(dict, key, SPC_TYPE_BOOL);
    item->value.value.u64 = value;
}

uint64_t spc_dictionary_get_uint64(spc_dictionary_t* dict, const char* key)
{
    spc_dictionary_item_t* item = spc_dictionary_lookup(dict, key);
    if (!item || item->value.type != SPC_TYPE_UINT64)
        return 0;

    return item->value.value.u64;
}

int64_t spc_dictionary_get_int64(spc_dictionary_t* dict, const char* key)
{
    spc_dictionary_item_t* item = spc_dictionary_lookup(dict, key);
    if (!item || item->value.type != SPC_TYPE_INT64)
        return 0;

    return item->value.value.i64;
}

const char* spc_dictionary_get_string(spc_dictionary_t* dict, const char* key)
{
    spc_dictionary_item_t* item = spc_dictionary_lookup(dict, key);
    if (!item || item->value.type != SPC_TYPE_STRING)
        return NULL;

    return item->value.value.str;
}

int spc_dictionary_get_bool(spc_dictionary_t* dict, const char* key)
{
    spc_dictionary_item_t* item = spc_dictionary_lookup(dict, key);
    if (!item || item->value.type != SPC_TYPE_BOOL)
        return 0;

    return item->value.value.u64;
}

mach_port_t spc_dictionary_get_send_port(spc_dictionary_t* dict, const char* key)
{
    spc_dictionary_item_t* item = spc_dictionary_lookup(dict, key);
    if (!item || item->value.type != SPC_TYPE_SEND_PORT)
        return MACH_PORT_NULL;

    mach_port_addref(item->value.value.port.name, MACH_PORT_RIGHT_SEND);
    return item->value.value.port.name;
}

mach_port_t spc_dictionary_get_receive_port(spc_dictionary_t* dict, const char* key)
{
    spc_dictionary_item_t* item = spc_dictionary_lookup(dict, key);
    if (!item || item->value.type != SPC_TYPE_RECV_PORT)
        return MACH_PORT_NULL;

    mach_port_addref(item->value.value.port.name, MACH_PORT_RIGHT_RECEIVE);
    return item->value.value.port.name;
}


void spc_dump_value(spc_value_t value, int indent)
{
    char* indent_str = malloc(indent + 1);
    memset(indent_str, ' ', indent);
    indent_str[indent] = 0;

    switch (value.type) {
        case SPC_TYPE_NULL:
            printf("%*cnull\n", indent, ' ');
            break;
        case SPC_TYPE_BOOL:
            printf("%*c%s\n", indent, ' ', value.value.u64 ? "true" : "false");
            break;
        case SPC_TYPE_UINT64:
            printf("%*c%llu\n", indent, ' ', value.value.u64);
            break;
        case SPC_TYPE_INT64:
            printf("%*c%lli\n", indent, ' ', value.value.i64);
            break;
        case SPC_TYPE_DOUBLE:
            printf("%*c%f\n", indent, ' ', value.value.dbl);
            break;
        case SPC_TYPE_STRING:
            printf("%*c%s\n", indent, ' ', value.value.str);
            break;
        case SPC_TYPE_UUID: {
            char buf[0x21];
            for (int i = 0; i < 0x10; i++) {
                sprintf(&buf[2*i], "%02x", ((unsigned char*)value.value.str)[i]);
            }
            buf[0x20] = 0;
            printf("%*cuuid: %s\n", indent, ' ', buf);
            break;
        }
        case SPC_TYPE_ARRAY: {
            spc_array_t* array = value.value.array;
            printf("%*c[\n", indent, ' ');
            for (size_t i = 0; i < array->length; i++) {
                spc_dump_value(array->values[i], indent + 2);
            }
            printf("%*c]\n", indent, ' ');
            break;
        }
        case SPC_TYPE_DICT: {
            spc_dictionary_item_t* current = value.value.dict->items;
            while (current) {
                printf("%*c%s:\n", indent, ' ', current->key);
                spc_dump_value(current->value, indent + 2);
                current = current->next;
            }
            break;
        }
        case SPC_TYPE_SEND_PORT:
            printf("%*cport send right: %d\n", indent, ' ', value.value.port.name);
            break;
        case SPC_TYPE_RECV_PORT:
            printf("%*cport receive right: %d\n", indent, ' ', value.value.port.name);
            break;
        case SPC_TYPE_DATA:
            printf("%*cdata: 0x", indent, ' ');
            for (size_t i = 0; i < value.value.data.size; i++)
                printf("%02x", value.value.data.ptr[i]);
            printf("\n");
            break;
        default:
            printf("%*cUnknown item of type %d\n", indent, ' ', value.type);
    }

    free(indent_str);
}

void spc_dump(spc_dictionary_t* dict)
{
    spc_value_t value;
    value.type = SPC_TYPE_DICT;
    value.value.dict = dict;
    spc_dump_value(value, 0);
}
