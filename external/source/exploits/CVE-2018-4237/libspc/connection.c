#include "datatypes.h"
#include "dictionary.h"
#include "serialization.h"
#include "utils.h"
#include "connection.h"

#include <stdlib.h>
#include <stdio.h>
#include <mach/mach.h>

spc_message_t* spc_recv(mach_port_t port)
{
    // TODO hack
    spc_mach_message_t* machmsg = malloc(0x10000);

    mach_msg_return_t kr = mach_msg(&machmsg->header, MACH_RCV_MSG, 0, 0x10000, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    ASSERT_MACH_SUCCESS(kr, "mach_msg_recv");

    spc_message_t* msg = spc_deserialize(machmsg);
    free(machmsg);
    return msg;
}

void spc_send(spc_message_t* msg)
{
    spc_mach_message_t* machmsg = spc_serialize(msg);

    mach_msg_return_t kr = mach_msg(&machmsg->header, MACH_SEND_MSG, machmsg->header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    ASSERT_MACH_SUCCESS(kr, "mach_msg_send");

    free(machmsg);
}

void spc_interface_routine(int subsytem_nr, int routine_nr, spc_dictionary_t* dict, spc_dictionary_t** reply)
{
    mach_port_t bootstrap_port;
    kern_return_t kr;

    spc_dictionary_set_uint64(dict, "subsystem", subsytem_nr);
    spc_dictionary_set_uint64(dict, "routine", routine_nr);

    kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port);
    ASSERT_MACH_SUCCESS(kr, "task_get_special_port");

    spc_message_t msg;
    msg.remote_port.name = bootstrap_port;
    msg.remote_port.type = MACH_MSG_TYPE_COPY_SEND;
    msg.local_port.name = mig_get_reply_port();
    msg.local_port.type = MACH_MSG_TYPE_MAKE_SEND_ONCE;
    msg.id = 0x10000000;
    msg.content = dict;

    spc_send(&msg);

    spc_message_t* reply_msg = spc_recv(mig_get_reply_port());

    *reply = reply_msg->content;
    free(reply_msg);
}

void spc_domain_routine(int routine_nr, spc_dictionary_t* msg, spc_dictionary_t** reply)
{
    return spc_interface_routine(3, routine_nr, msg, reply);
}

kern_return_t spc_look_up_endpoint(const char* name, uint64_t type, uint64_t handle, uint64_t lookup_handle, uint64_t flags, mach_port_t* remote_port)
{
    spc_dictionary_t* msg = spc_dictionary_create();
    spc_dictionary_set_string(msg, "name", name);
    spc_dictionary_set_uint64(msg, "type", type);
    spc_dictionary_set_uint64(msg, "handle", handle);
    spc_dictionary_set_uint64(msg, "lookup-handle", lookup_handle);
    spc_dictionary_set_uint64(msg, "flags", flags);

    spc_dictionary_t* reply;

    spc_domain_routine(0x324, msg, &reply);
    spc_dictionary_destroy(msg);

    if (spc_dictionary_get_int64(reply, "error") != 0) {
        return KERN_FAILURE;
    }

    *remote_port = spc_dictionary_get_send_port(reply, "port");
    spc_dictionary_destroy(reply);

    return KERN_SUCCESS;
}

spc_connection_t* spc_create_connection_mach_port(mach_port_t service_port)
{
    kern_return_t kr;
    mach_port_t send_port, receive_port;

    // Allocate send port. Receive right will be transferred to remote end.
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &send_port);
    ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");

    // Allocate receive port. A send right will be created and send to the remote end.
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive_port);
    ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");

    spc_connection_t* connection = malloc(sizeof(spc_connection_t));
    connection->receive_port = receive_port;

    // Extract a send right for the send_port.
    mach_msg_type_name_t aquired_type;
    kr = mach_port_extract_right(mach_task_self(), send_port, MACH_MSG_TYPE_MAKE_SEND, &connection->send_port, &aquired_type);
    ASSERT_MACH_SUCCESS(kr, "mach_port_extract_right");

    struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t send_port;
        mach_msg_port_descriptor_t receive_port;
    } msg;

    msg.header.msgh_remote_port = service_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_id = 1999646836;            // Copy-pasted from mach message trace

    msg.body.msgh_descriptor_count = 2;

    msg.send_port.type = MACH_MSG_PORT_DESCRIPTOR;
    msg.send_port.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    msg.send_port.name = send_port;

    msg.receive_port.type = MACH_MSG_PORT_DESCRIPTOR;
    msg.receive_port.disposition = MACH_MSG_TYPE_MAKE_SEND;
    msg.receive_port.name = receive_port;

    kr = mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    ASSERT_MACH_SUCCESS(kr, "mach_msg_send");

    return connection;
}

spc_connection_t* spc_create_connection_mach_service(const char* service_name)
{
    kern_return_t  kr;
    mach_port_t service_port;

    kr = spc_look_up_endpoint(service_name, 7, 0, 0, 0, &service_port);
    if (kr != KERN_SUCCESS) {
        return NULL;
    }

    return spc_create_connection_mach_port(service_port);
}

spc_connection_t* spc_accept_connection(mach_port_t port)
{
    struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t recv_port;
        mach_msg_port_descriptor_t send_port;
        mach_msg_trailer_t trailer;
    } msg;

    mach_msg_return_t kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    ASSERT_MACH_SUCCESS(kr, "mach_msg_recv");

    spc_connection_t* connection = malloc(sizeof(spc_connection_t));
    connection->receive_port = msg.recv_port.name;
    connection->send_port = msg.send_port.name;

    return connection;
}

void spc_connection_send(spc_connection_t* connection, spc_dictionary_t* dict)
{
    spc_message_t msg;
    msg.id = 0x10000000;
    msg.remote_port.name = connection->send_port;
    msg.remote_port.type = MACH_MSG_TYPE_COPY_SEND;
    msg.local_port.name = MACH_PORT_NULL;
    msg.local_port.type = 0;
    msg.content = dict;
    spc_send(&msg);
}

spc_dictionary_t* spc_connection_send_with_reply(spc_connection_t* connection, spc_dictionary_t* dict)
{
    spc_message_t msg;
    msg.id = 0x10000000;
    msg.remote_port.name = connection->send_port;
    msg.remote_port.type = MACH_MSG_TYPE_COPY_SEND;
    msg.local_port.name = mig_get_reply_port();
    msg.local_port.type = MACH_MSG_TYPE_MAKE_SEND_ONCE;
    msg.content = dict;
    spc_send(&msg);

    spc_message_t* reply = spc_recv(msg.local_port.name);
    dict = reply->content;
    free(reply);

    return dict;
}

spc_dictionary_t* spc_connection_recv(spc_connection_t* connection)
{
    spc_message_t* msg = spc_recv(connection->receive_port);

    spc_dictionary_t* dict = msg->content;
    free(msg);

    return dict;
}

void spc_reply(spc_message_t* orig, spc_dictionary_t* reply)
{
    spc_message_t msg;
    msg.id = 0x20000000;
    msg.remote_port.name = orig->local_port.name;
    msg.remote_port.type = MACH_MSG_TYPE_MOVE_SEND_ONCE;
    msg.local_port.name = MACH_PORT_NULL;
    msg.local_port.type = 0;
    msg.content = reply;
    spc_send(&msg);
}
