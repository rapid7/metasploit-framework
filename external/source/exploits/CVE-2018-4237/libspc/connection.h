#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "datatypes.h"

void spc_interface_routine(int subsytem_nr, int routine_nr, spc_dictionary_t* msg, spc_dictionary_t** reply);
void spc_domain_routine(int routine_nr, spc_dictionary_t* msg, spc_dictionary_t** reply);

kern_return_t spc_look_up_endpoint(const char* name, uint64_t type, uint64_t handle, uint64_t lookup_handle, uint64_t flags, mach_port_t* remote_port);
spc_connection_t* spc_create_connection_mach_port(mach_port_t service_port);
spc_connection_t* spc_create_connection_mach_service(const char* service_name);

spc_connection_t* spc_accept_connection(mach_port_t port);

// Low-level send/recv API
void spc_send(spc_message_t* msg);
spc_message_t* spc_recv(mach_port_t port);
void spc_reply(spc_message_t* msg, spc_dictionary_t* reply);

// High-level send/recv API
void spc_connection_send(spc_connection_t* connection, spc_dictionary_t* msg);
spc_dictionary_t* spc_connection_send_with_reply(spc_connection_t* connection, spc_dictionary_t* msg);
spc_dictionary_t* spc_connection_recv(spc_connection_t* connection);

#endif
