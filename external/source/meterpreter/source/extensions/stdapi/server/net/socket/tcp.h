#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_NET_TCP_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_NET_TCP_H

DWORD tcp_channel_client_write( Channel *channel, Packet *request, LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten);
DWORD tcp_channel_client_close(Channel *channel, Packet *request, LPVOID context);
DWORD tcp_channel_client_local_notify(Remote *remote, TcpClientContext *ctx);

#endif