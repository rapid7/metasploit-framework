#include "precomp.h"
#include "tcp.h"

/*********************************
 * TCP Client Channel Operations *
 *********************************/

/*
 * Writes data from the remote half of the channel to the established connection.
 */
DWORD tcp_channel_client_write( Channel *channel, Packet *request, LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten)
{
	DWORD dwResult         = ERROR_SUCCESS;
	TcpClientContext * ctx = NULL;
	LONG written           = 0;

	do
	{
		dprintf( "[TCP] tcp_channel_client_write. channel=0x%08X, buffsize=%d", channel, bufferSize );

		ctx = (TcpClientContext *)context;
		if( !ctx )
			BREAK_WITH_ERROR( "[TCP] tcp_channel_client_write. ctx == NULL", ERROR_INVALID_HANDLE );

		written = send( ctx->fd, buffer, bufferSize, 0 );

		if( written == SOCKET_ERROR )
		{
			dwResult = WSAGetLastError();

			if( dwResult == WSAEWOULDBLOCK )
			{
				struct timeval tv = {0};
				fd_set set        = {0};
				DWORD res         = 0;

				dprintf( "[TCP] tcp_channel_client_write. send returned WSAEWOULDBLOCK, waiting until we can send again..." );

				while( TRUE )
				{
					tv.tv_sec  = 0;
					tv.tv_usec = 1000;

					FD_ZERO( &set );
					FD_SET( ctx->fd, &set );

					res = select( 0, NULL, &set, NULL, &tv );
					if( res > 0 )
					{
						dwResult = ERROR_SUCCESS;
						break;
					}
					else if( res == SOCKET_ERROR )
					{
						dwResult = WSAGetLastError();
						break;
					}

					Sleep( 100 );
				}

				if( dwResult == ERROR_SUCCESS )
					continue;
				else
					dprintf( "[TCP] tcp_channel_client_write. select == SOCKET_ERROR. dwResult=%d", dwResult );
			}

			written = 0;
			dprintf( "[TCP] tcp_channel_client_write. written == SOCKET_ERROR. dwResult=%d", dwResult );
		}

		if( bytesWritten )
			*bytesWritten = written;

	} while( 0 );

	dprintf( "[TCP] tcp_channel_client_write. finished. dwResult=%d, written=%d", dwResult, written );

	return dwResult;
}

/*
 * Closes the established connection and cleans up stale state
 */
DWORD tcp_channel_client_close(Channel *channel, Packet *request, LPVOID context)
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
 * Callback for when there is data available on the local side of the TCP client connection
 */
DWORD tcp_channel_client_local_notify( Remote * remote, TcpClientContext * ctx )
{
	struct timeval tv  = {0};
	fd_set set         = {0};
	UCHAR  buf[16384]  = {0};
	LONG   dwBytesRead = 0;

	// We select in a loop with a zero second timeout because it's possible
	// that we could get a recv notification and a close notification at once,
	// so we need some way to make sure that we see them both, otherwise the
	// event handle wont get re set to notify us.
	do
	{
		// Reset the notification event
		ResetEvent( ctx->notify );

		FD_ZERO( &set );
		FD_SET( ctx->fd, &set );
		
		tv.tv_sec  = 0;
		tv.tv_usec = 0;

		// Read data from the client connection
		dwBytesRead = recv( ctx->fd, buf, sizeof(buf), 0 );
		
		if( dwBytesRead == SOCKET_ERROR )
		{
			DWORD dwError = WSAGetLastError();
			
			// WSAECONNRESET: The connection was forcibly closed by the remote host.
			// WSAECONNABORTED: The connection was terminated due to a time-out or other failure.
			if( dwError == WSAECONNRESET || dwError == WSAECONNABORTED )
			{
				dprintf( "[TCP] tcp_channel_client_local_notify. [error] closing down channel gracefully. WSAGetLastError=%d", dwError );
				// By setting bytesRead to zero, we can ensure we close down the channel gracefully...
				dwBytesRead = 0;
			}
			else if( dwError == WSAEWOULDBLOCK )
			{
				dprintf( "[TCP] tcp_channel_client_local_notify. channel=0x%08X. recv generated a WSAEWOULDBLOCK", ctx->channel );
				// break and let the scheduler notify us again if needed.
				break;
			}
			else
			{
				dprintf( "[TCP] tcp_channel_client_local_notify. [error] channel=0x%08X read=0x%.8x (ignored). WSAGetLastError=%d", ctx->channel, dwBytesRead, dwError );
				// we loop again because bytesRead is -1.
			}
		}

		if( dwBytesRead == 0 )
		{
			dprintf( "[TCP] tcp_channel_client_local_notify. [closed] channel=0x%08X read=0x%.8x", ctx->channel, dwBytesRead );

			// Set the native channel operations context to NULL
			channel_set_native_io_context( ctx->channel, NULL );
			
			// Sleep for a quarter second
			Sleep( 250 );

			// Free the context
			free_tcp_client_context( ctx );

			// Stop processing
			break;
		}
		else if( dwBytesRead > 0 )
		{
			if( ctx->channel )
			{
				dprintf( "[TCP] tcp_channel_client_local_notify. [data] channel=0x%08X read=%d", ctx->channel, dwBytesRead );
				channel_write( ctx->channel, ctx->remote, NULL, 0, buf, dwBytesRead, 0 );
			}
			else
			{
				dprintf( "[TCP] tcp_channel_client_local_notify. [data] channel=<invalid> read=0x%.8x", dwBytesRead );
			}
		}

	} while( select( 1, &set, NULL, NULL, &tv ) > 0 );
	
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
		if ((result = create_tcp_client_channel(remote, host, (USHORT)(port & 0xffff), &channel)) != ERROR_SUCCESS)
			break;

		// Set the channel's identifier on the response
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(channel));

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
DWORD create_tcp_client_channel(Remote *remote, LPCSTR remoteHost, USHORT remotePort, Channel **outChannel)
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
		if ((clientFd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0)) == INVALID_SOCKET)
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
		if (!(ctx = (TcpClientContext *)malloc( sizeof(TcpClientContext))))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Initialize the context attributes
		memset(ctx, 0, sizeof(TcpClientContext));

		ctx->remote = remote;
		ctx->fd     = clientFd;

		// Initialize the channel operations structure
		memset(&chops, 0, sizeof(chops));

		chops.native.context = ctx;
		chops.native.write   = tcp_channel_client_write;
		chops.native.close   = tcp_channel_client_close;

		dprintf( "[TCP] create_tcp_client_channel. host=%s, port=%d creating the channel", remoteHost, remotePort );
		// Allocate an uninitialized channel for associated with this connection
		if (!(channel = channel_create_stream(0, 0,&chops)))
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

			scheduler_insert_waitable( ctx->notify, ctx, (WaitableNotifyRoutine)tcp_channel_client_local_notify);
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
	DWORD dwResult      = ERROR_SUCCESS;
	Packet * response   = NULL;
	SocketContext * ctx = NULL;
	Channel * channel   = NULL;
	DWORD cid           = 0;
	DWORD how           = 0;

	do
	{
		dprintf( "[TCP] entering request_net_socket_tcp_shutdown" );
		response = packet_create_response( packet );
		if( !response )
			BREAK_WITH_ERROR( "[TCP] request_net_socket_tcp_shutdown. response == NULL", ERROR_NOT_ENOUGH_MEMORY );

		cid = packet_get_tlv_value_uint( packet, TLV_TYPE_CHANNEL_ID );
		how = packet_get_tlv_value_uint( packet, TLV_TYPE_SHUTDOWN_HOW );

		channel = channel_find_by_id( cid );
		if( !response )
			BREAK_WITH_ERROR( "[TCP] request_net_socket_tcp_shutdown. channel == NULL", ERROR_INVALID_HANDLE );

		dprintf( "[TCP] request_net_socket_tcp_shutdown. channel=0x%08X, cid=%d", channel, cid );

		ctx = channel_get_native_io_context( channel );
		if( !ctx )
			BREAK_WITH_ERROR( "[TCP] request_net_socket_tcp_shutdown. ctx == NULL", ERROR_INVALID_HANDLE );

		if( shutdown( ctx->fd, how ) == SOCKET_ERROR )
			BREAK_ON_WSAERROR( "[TCP] request_net_socket_tcp_shutdown. shutdown failed" );

		// sf: we dont seem to need to call this here, as the channels tcp_channel_client_local_notify() will 
		// catch the socket closure and call free_socket_context() for us, due the the FD_READ|FD_CLOSE flags 
		// being passed to WSAEventSelect for the notify event in create_tcp_client_channel().
		// This avoids a double call (from two different threads) and subsequent access violation in some edge cases.
		//free_socket_context( ctx );

	} while( 0 );

	packet_transmit_response( dwResult, remote, response );

	dprintf( "[TCP] leaving request_net_socket_tcp_shutdown" );
	
	return ERROR_SUCCESS;
}
