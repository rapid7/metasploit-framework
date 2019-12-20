#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#include <stdint.h>
#include <mach/mach.h>

typedef struct {
    mach_port_t send_port;          // A send right to a port on which the remote end can receive
    mach_port_t receive_port;
} spc_connection_t;

#define SPC_TYPE_NULL         0x1000
#define SPC_TYPE_BOOL         0x2000
#define SPC_TYPE_INT64        0x3000
#define SPC_TYPE_UINT64       0x4000
#define SPC_TYPE_DOUBLE       0x5000
#define SPC_TYPE_DATA         0x8000
#define SPC_TYPE_STRING       0x9000
#define SPC_TYPE_UUID         0xa000
#define SPC_TYPE_FD           0xb000
#define SPC_TYPE_SHMEM        0xc000
#define SPC_TYPE_SEND_PORT    0xd000
#define SPC_TYPE_ARRAY        0xe000
#define SPC_TYPE_DICT         0xf000
#define SPC_TYPE_RECV_PORT    0x15000

typedef struct _spc_dictionary_t spc_dictionary_t;
typedef struct _spc_array_t spc_array_t;

typedef struct {
    mach_port_t name;
    mach_msg_type_name_t type;
} spc_port_t;

const spc_port_t SPC_NULL_PORT;

typedef struct {
    unsigned char* ptr;
    size_t size;
} spc_data_t;

typedef struct {
    uint32_t type;
    union {
        uint64_t u64;
        int64_t i64;
        double dbl;
        char* str;
        void* ptr;
        spc_data_t data;
        spc_dictionary_t* dict;
        spc_array_t* array;
        spc_port_t port;
    } value;
} spc_value_t;

spc_value_t spc_null_create();
void spc_value_destroy(spc_value_t value);

typedef struct _spc_array_t {
    spc_value_t* values;
    size_t length;
    size_t capacity;
} spc_array_t;

typedef struct _spc_dictionary_item_t {
    char* key;
    spc_value_t value;
    struct _spc_dictionary_item_t* next;
} spc_dictionary_item_t;

typedef struct _spc_dictionary_t {
    spc_dictionary_item_t* items;
    size_t num_items;
} spc_dictionary_t;


void spc_array_destroy(spc_array_t* dict);
void spc_dictionary_destroy(spc_dictionary_t* dict);

// A message is essentially a mach message header and a dictionary
typedef struct {
    spc_port_t local_port;
    spc_port_t remote_port;
    unsigned int id;
    spc_dictionary_t* content;
} spc_message_t;

void spc_message_destroy(spc_message_t* msg);

#endif
