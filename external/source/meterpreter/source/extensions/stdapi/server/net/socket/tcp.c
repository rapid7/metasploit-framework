#include "precomp.h"

/*********************************
 * TCP Client Channel Operations *
 *********************************/

/*
 * Writes data from the remote half of the channel to the established 
 * connection.
 */
static DWORD tcp_channel_client_write(Channel *channel, Packet *request, 
		LPVOID context, LPVOID buffer, DWORD bufferSize,
		LPDWORD bytesWritten)
{
	TcpClientContext *ctx = (TcpClientContext *)context;
	DWORD result= ERROR_SUCCESS;
	LONG written = 0;

	dprintf( "[TCP] tcp_channel_client_write. channel=0x%08X, buffsize=%d", channel, bufferSize );

	// Write a chunk
	if ((written = send(ctx->fd, buffer, bufferSize, 0)) <= 0)
	{
		written = 0;
		result  = GetLastError();
	}

	// Set bytesWritten
	if (bytesWritten)
		*bytesWritten = written;

	return result;
}

/*
 * Closes the established connection and cleans up stale state
 */
static DWORD tcp_channel_client_close(Channel *channel, Packet *request, 
		LPVOID context)
{
	TcpClientContext *ctx = (TcpClientContext *)context;

	dprintf( "[TCP] tcp_channel_client_close. channel=0x%08X, ctx=0x%08X", channel, ctx );

	if (ctx)
	{
		// Set the context channel to NULL so we don't try to close the
		// channel (since it's already being closed)
		ctx->channel = NULL;

		// Free the context
		free_tcp_client_context(ctx);

		// Set the native channel operations context to NULL
		channel_set_native_io_context(channel, NULL);
	}

	return ERROR_SUCCESS;
}

/*
 * Callback for when there is data available on the local side of the TCP
 * client connection
 */
static DWORD tcp_channel_client_local_notify(Remote *remote, 
		TcpClientContext *ctx)
{
	struct timeval tv;
	fd_set set;
	UCHAR  buf[16384];
	LONG   bytesRead;

	// Reset the notification event
	ResetEvent(ctx->notify);

	tv.tv_sec  = 0;
	tv.tv_usec = 0;

	// We select in a loop with a zero second timeout because it's possible
	// that we could get a recv notification and a close notification at once,
	// so we need some way to make sure that we see them both, otherwise the
	// event handle wont get re set to notify us.
	do
	{
		FD_ZERO(&set);
		FD_SET(ctx->fd, &set);

		// Read data from the client connection
		bytesRead = recv(ctx->fd, buf, sizeof(buf), 0);
		
		// Not sure why we get these with pending data
		if(bytesRead == SOCKET_ERROR) {
			printf( "[TCP] tcp_channel_client_local_notify. [error] channel=0x%08X read=0x%.8x (ignored)", ctx->channel, bytesRead );
			continue;
		}

		if (bytesRead == 0) {
			dprintf( "[TCP] tcp_channel_client_local_notify. [closed] channel=0x%08X read=0x%.8x", ctx->channel, bytesRead );

			// Set the native channel operations context to NULL
			channel_set_native_io_context(ctx->channel, NULL);
			
			// Sleep for a quarter second
			Sleep(250);

			// Free the context
			free_tcp_client_context(ctx);

			// Stop processing
			break;
		}
		
		if (ctx->channel) {
			// dprintf( "[TCP] tcp_channel_client_local_notify. [data] channel=0x%08X read=0x%.8x", ctx->channel, bytesRead );
			channel_write(ctx->channel, ctx->remote, NULL, 0, buf, bytesRead, 0);
		} else {
			dprintf( "[TCP] tcp_channel_client_local_notify. [data] channel=<invalid> read=0x%.8x", bytesRead );
		}
	
	} while (select(0, &set, NULL, NULL, &tv) > 0);
	
	return ERROR_SUCCESS;
}

/*
 * Allocates a streaming TCP channel
 *
 * TLVs:
 *
 * req: TLV_TYPE_HOST_NAME - The host to connect to
 * req: TLV_TYPE_PORT      - The port to connect to
 */
DWORD request_net_tcp_client_channel_open(Remote *remote, Packet *packet)
{
	Channel *channel = NULL;
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	LPCSTR host;
	DWORD port;

	do
	{
		// No response packet?
		if (!response)
			break;

		// Extract the hostname and port that we are to connect to
		host = packet_get_tlv_value_string(packet, TLV_TYPE_PEER_HOST);
		port = packet_get_tlv_value_uint(packet, TLV_TYPE_PEER_PORT);
	
		// Open the TCP channel
		if ((result = create_tcp_client_channel(remote, host, 
				(USHORT)(port & 0xffff), &channel)) != ERROR_SUCCESS)
			break;

		// Set the channel's identifier on the response
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID,
				channel_get_id(channel));

	} while (0);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Creates a connection to a remote host and builds a logical channel to 
 * represent it.
 *
 */
DWORD create_tcp_client_channel(Remote *remote, LPCSTR remoteHost, 
		USHORT remotePort, Channel **outChannel)
{
	StreamChannelOps chops;
	TcpClientContext *ctx = NULL;
	DWORD result = ERROR_SUCCESS;
	Channel *channel = NULL;
	struct sockaddr_in s;
	SOCKET clientFd = 0;

	if (outChannel)
		*outChannel = NULL;

	dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d", remoteHost, remotePort );

	do
	{
		// Allocate a client socket
		if ((clientFd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0)) 
				== INVALID_SOCKET)
		{
			clientFd = 0;
			result   = GetLastError();
			break;
		}
 
		s.sin_family      = AF_INET;
		s.sin_port        = htons(remotePort);
		s.sin_addr.s_addr = inet_addr(remoteHost);


		// Resolve the host name locally
		if (s.sin_addr.s_addr == (DWORD)-1)
		{
			struct hostent *h;

			if (!(h = gethostbyname(remoteHost)))
			{
				result = GetLastError();
				break;
			}

			memcpy(&s.sin_addr.s_addr, h->h_addr, h->h_length);
		}

		dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d connecting...", remoteHost, remotePort );
		// Try to connect to the host/port
		if (connect(clientFd, (struct sockaddr *)&s, sizeof(s)) == SOCKET_ERROR)
		{
			result = GetLastError();
			break;
		}

		dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d connected!", remoteHost, remotePort );
		// Allocate the client context for tracking the connection
		if (!(ctx = (TcpClientContext *)malloc(
				sizeof(TcpClientContext))))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Initialize the context attributes
		memset(ctx, 0, sizeof(TcpClientContext));

		ctx->remote = remote;
		ctx->fd     = clientFd;
		ctx->mutex  = CreateMutex(NULL, FALSE, NULL);

		// Initialize the channel operations structure
		memset(&chops, 0, sizeof(chops));

		chops.native.context = ctx;
		chops.native.write   = tcp_channel_client_write;
		chops.native.close   = tcp_channel_client_close;

		dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d creating the channel", remoteHost, remotePort );
		// Allocate an uninitialized channel for associated with this connection
		if (!(channel = channel_create_stream(0, 0,
				&chops)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
	
		// Save the channel context association
		ctx->channel = channel;

		// Finally, create a waitable event and insert it into the scheduler's 
		// waitable list
		dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d creating the notify", remoteHost, remotePort );
		if ((ctx->notify = WSACreateEvent()))
		{
			WSAEventSelect(ctx->fd, ctx->notify, FD_READ|FD_CLOSE);
			dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d created the notify %.8x", remoteHost, remotePort, ctx->notify );

			scheduler_insert_waitable( ctx->notify, ctx,
					(WaitableNotifyRoutine)tcp_channel_client_local_notify);
		}

	} while (0);

	dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d all done", remoteHost, remotePort );

	// Clean up on failure
	if (result != ERROR_SUCCESS)
	{
		dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d cleaning up failed connection", remoteHost, remotePort );
		if (ctx)
			free_tcp_client_context(ctx);
		if (clientFd)
			closesocket(clientFd);

		channel = NULL;
	}

	if (outChannel)
		*outChannel = channel;

	return result;
}

/*
 * Deallocates and cleans up the attributes of a socket context
 */
VOID free_socket_context(SocketContext *ctx)
{
	dprintf( "[TCP] free_socket_context. ctx=0x%08X", ctx );

	// Close the socket and notification handle
	if (ctx->fd){
		closesocket(ctx->fd);
		ctx->fd = 0;
	}
	
	if (ctx->channel) {
		channel_close(ctx->channel, ctx->remote, NULL, 0, NULL);
		ctx->channel = NULL;
	}

	if (ctx->notify)
	{
		dprintf( "[TCP] free_socket_context. remove_waitable ctx=0x%08X notify=0x%08X", ctx, ctx->notify);
		// The scheduler calls CloseHandle on our WSACreateEvent() for us
		scheduler_remove_waitable(ctx->notify);
		ctx->notify = NULL;
	}

	// Free the context
	free(ctx);
}

/*
 * Shuts the socket down for either reading or writing based on the how
 * parameter supplied by the remote side
 */
DWORD request_net_socket_tcp_shutdown(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	SocketContext *ctx = NULL;
	Channel *channel = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD how;
	dprintf( "[TCP] entering request_net_socket_tcp_shutdown" );

	// Find the associated channel
	channel = channel_find_by_id(packet_get_tlv_value_uint(packet,  TLV_TYPE_CHANNEL_ID));

	how = packet_get_tlv_value_uint(packet, TLV_TYPE_SHUTDOWN_HOW);

	dprintf( "[TCP] request_net_socket_tcp_shutdown. channel=0x%08X", channel );

	// If the channel and channel context are valid...
	if ((channel) &&
	    ((ctx = channel_get_native_io_context(channel))))
	{
		if (shutdown(ctx->fd, how) == SOCKET_ERROR)
			result = WSAGetLastError();
		else
			free_socket_context( ctx );
	}

	packet_transmit_response(result, remote, response);
	dprintf( "[TCP] leaving request_net_socket_tcp_shutdown" );
	return ERROR_SUCCESS;
}
