
#ifndef _DICTIONARY_H_
#define _DICTIONARY_H_

#include "datatypes.h"

spc_dictionary_t* spc_dictionary_create();

void spc_dictionary_set_value(spc_dictionary_t* dict, const char* key, spc_value_t value);
void spc_dictionary_set_string(spc_dictionary_t* dict, const char* key, const char* value);
void spc_dictionary_set_uint64(spc_dictionary_t* dict, const char* key, uint64_t value);
void spc_dictionary_set_int64(spc_dictionary_t* dict, const char* key, int64_t value);
void spc_dictionary_set_bool(spc_dictionary_t* dict, const char* key, int value);
void spc_dictionary_set_data(spc_dictionary_t* dict, const char* key, const void* value, size_t len);
void spc_dictionary_set_send_port(spc_dictionary_t* dict, const char* key, mach_port_t port);
void spc_dictionary_set_receive_port(spc_dictionary_t* dict, const char* key, mach_port_t port);
void spc_dictionary_set_fd(spc_dictionary_t* dict, const char* key, int fd);

spc_dictionary_item_t* spc_dictionary_lookup(spc_dictionary_t* dict, const char* key);

mach_port_t spc_dictionary_get_send_port(spc_dictionary_t* dict, const char* key);
mach_port_t spc_dictionary_get_receive_port(spc_dictionary_t* dict, const char* key);
uint64_t spc_dictionary_get_uint64(spc_dictionary_t* dict, const char* key);
uint64_t spc_dictionary_get_int64(spc_dictionary_t* dict, const char* key);
const char* spc_dictionary_get_string(spc_dictionary_t* dict, const char* key);
int spc_dictionary_get_bool(spc_dictionary_t* dict, const char* key);

void spc_dump(spc_dictionary_t* dict);

#endif
