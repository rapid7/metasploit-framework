#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_NET_NET_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_NET_NET_H

/*
 * Generic socket context
 */
typedef struct _SocketContext
{
	Remote   *remote;
	Channel  *channel;
#ifdef _WIN32
	WSAEVENT notify;
#else
	int notify;
#endif
	SOCKET   fd;
} SocketContext;

typedef SocketContext TcpClientContext;
typedef SocketContext UdpClientContext;

#define free_tcp_client_context(x) free_socket_context((SocketContext *)x)
#define free_udp_client_context(x) free_socket_context((SocketContext *)x)

/*
 * Request handlers
 */
DWORD request_net_tcp_client_channel_open(Remote *remote, Packet *packet);

// Config
DWORD request_net_config_get_routes(Remote *remote, Packet *packet);
DWORD request_net_config_add_route(Remote *remote, Packet *packet);
DWORD request_net_config_remove_route(Remote *remote, Packet *packet);

DWORD request_net_config_get_interfaces(Remote *remote, Packet *packet);

// Socket
DWORD request_net_socket_tcp_shutdown(Remote *remote, Packet *packet);

/*
 * Channel creation
 */
DWORD create_tcp_client_channel(Remote *remote, LPCSTR host,
		USHORT port, Channel **outChannel);

VOID free_socket_context(SocketContext *ctx);


#endif
