#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SYS_REGISTRY_REGISTRY_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SYS_REGISTRY_REGISTRY_H

/*
 * Registry interaction packet handlers
 */
DWORD request_registry_open_key(Remote *remote, Packet *packet);
DWORD request_registry_open_remote_key(Remote *remote, Packet *packet);
DWORD request_registry_create_key(Remote *remote, Packet *packet);
DWORD request_registry_enum_key(Remote *remote, Packet *packet);
DWORD request_registry_delete_key(Remote *remote, Packet *packet);
DWORD request_registry_close_key(Remote *remote, Packet *packet);
DWORD request_registry_set_value(Remote *remote, Packet *packet);
DWORD request_registry_query_value(Remote *remote, Packet *packet);
DWORD request_registry_query_class(Remote *remote, Packet *packet);
DWORD request_registry_enum_value(Remote *remote, Packet *packet);
DWORD request_registry_delete_value(Remote *remote, Packet *packet);

#endif
