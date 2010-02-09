#include "precomp.h"
#include "udp.h"

/*
 * Write data from the channel to the remote UDP peer. The core_channel_write request can optionally 
 * specify a peer host/port for the sendto(), if no peer host/port is specified the default peer 
 * host/port is used as supplied in the origional channel open request.
 */
DWORD udp_channel_write( Channel * channel, Packet * request, LPVOID context, LPVOID buffer, DWORD dwBufferSize, LPDWORD bytesWritten )
{
	DWORD dwResult         = ERROR_SUCCESS;
	UdpClientContext * ctx = NULL;
	SOCKADDR_IN saddr      = {0};
	DWORD dwWritten        = 0;
	SHORT rport            = 0;
	char * host            = 0;
	unsigned long rhost    = 0;

	do
	{
		ctx = (UdpClientContext *)context;
		if( !ctx )
			BREAK_WITH_ERROR( "[UDP] udp_channel_write. ctx == NULL", ERROR_INVALID_HANDLE );
		
		rport = (USHORT)( packet_get_tlv_value_uint( request, TLV_TYPE_PEER_PORT ) & 0xFFFF );
		if( !rport )
		{
			rport = ctx->peerport;
			if( !rport )
				BREAK_WITH_ERROR( "[UDP] udp_channel_write. A peer port must be specified", ERROR_INVALID_PARAMETER );
		}

		host = packet_get_tlv_value_string( request, TLV_TYPE_PEER_HOST );
		if( !host )
		{
			rhost = ctx->peerhost.s_addr;
			if( !rhost )
				BREAK_WITH_ERROR( "[UDP] udp_channel_write. A peer host must be specified", ERROR_INVALID_PARAMETER );
		}
		else
		{
			rhost = inet_addr( host );
		}

		saddr.sin_family      = AF_INET;
		saddr.sin_port        = htons( rport );
		saddr.sin_addr.s_addr = rhost;

		dprintf( "[UDP] udp_channel_write. channel=0x%08X, buffsize=%d to %s:%d", channel, dwBufferSize, inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port) );

		dwWritten = sendto( ctx->sock.fd, buffer, dwBufferSize, 0, (SOCKADDR *)&saddr, sizeof(SOCKADDR_IN) );

		if( dwWritten == SOCKET_ERROR )
		{
			dwResult = WSAGetLastError();

			if( dwResult == WSAEWOULDBLOCK )
			{
				struct timeval tv = {0};
				fd_set set        = {0};
				DWORD res         = 0;

				dprintf( "[UDP] udp_channel_write. sendto returned WSAEWOULDBLOCK, waiting until we can send again..." );

				while( TRUE )
				{
					tv.tv_sec  = 0;
					tv.tv_usec = 1000;

					FD_ZERO( &set );
					FD_SET( ctx->sock.fd, &set );

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
					dprintf( "[UDP] udp_channel_write. select == SOCKET_ERROR. dwResult=%d", dwResult );
			}

			dwWritten = 0;
			dprintf( "[UDP] udp_channel_write. written == SOCKET_ERROR. dwResult=%d", dwResult );
		}

		if( bytesWritten )
			*bytesWritten = dwWritten;

	} while( 0 );

	dprintf( "[UDP] udp_channel_write. finished. dwResult=%d, dwWritten=%d", dwResult, dwWritten );

	return dwResult;
}

/*
 * Free's a UDP channels context, closing the socket and channel.
 */
VOID free_udp_context( UdpSocketContext * ctx )
{
	dprintf( "[UDP] free_udp_context. ctx=0x%08X", ctx );

	// Close the socket and notification handle
	if( ctx->sock.fd )
	{
		closesocket( ctx->sock.fd );
		ctx->sock.fd = 0;
	}
	
	if( ctx->sock.channel )
	{
		channel_close( ctx->sock.channel, ctx->sock.remote, NULL, 0, NULL );
		ctx->sock.channel = NULL;
	}

	if( ctx->sock.notify )
	{
		dprintf( "[UDP] free_udp_context. remove_waitable ctx=0x%08X notify=0x%08X", ctx, ctx->sock.notify );
		// The scheduler calls CloseHandle on our WSACreateEvent() for us
		scheduler_remove_waitable( ctx->sock.notify );
		ctx->sock.notify = NULL;
	}

	// Free the context
	free( ctx );
}

/*
 * The notify routine for all FD_READ events on the UDP socket.
 */
DWORD udp_channel_notify( Remote * remote, UdpClientContext * ctx )
{
	DWORD dwResult     = ERROR_SUCCESS;
	SOCKADDR_IN from   = {0};
	DWORD dwFromLength = 0;
	DWORD dwBytesRead  = 0;
	BYTE bBuffer[65535];

	do
	{
		ResetEvent( ctx->sock.notify );

		dwFromLength = sizeof( SOCKADDR_IN );

		dwBytesRead = recvfrom( ctx->sock.fd, bBuffer, 65535, 0, (SOCKADDR *)&from, &dwFromLength );
		if( dwBytesRead == SOCKET_ERROR )
		{
			DWORD dwError = WSAGetLastError();

			if( dwError == WSAECONNRESET )
			{
				dprintf( "[UDP] udp_channel_notify. WSAECONNRESET for channel=0x%08X, WSAGetLastError=%d", ctx->sock.channel, dwError );
				// sf: here we have a valid host which sent back an ICMP Port Unreachable message for a previous sendto()
				// we should not close the socket (ctx->sock.fd)
			}
			else
			{
				dprintf( "[UDP] udp_channel_notify. Error on recvfrom with channel=0x%08X, WSAGetLastError=%d", ctx->sock.channel, dwError );
			}

			break;
		}

		if( dwBytesRead == 0 )
		{
			dprintf( "[UDP] udp_channel_notify. channel=0x%08X is being gracefully closed...", ctx->sock.channel );

			channel_set_native_io_context( ctx->sock.channel, NULL );
			
			Sleep( 250 );

			free_udp_context( ctx );

			break;
		}
		else if( dwBytesRead > 0 )
		{
			char * cpPeerHost = NULL;
			Tlv addend[2]     = {0};
			DWORD dwPeerPort  = 0;

			if( !ctx->sock.channel )
				break;

			cpPeerHost = inet_ntoa( from.sin_addr );
			if( !cpPeerHost )
				cpPeerHost = "0.0.0.0";

			dwPeerPort = htonl( ntohs( from.sin_port ) );

			addend[0].header.type   = TLV_TYPE_PEER_HOST;
			addend[0].header.length = (DWORD)(strlen(cpPeerHost) + 1);
			addend[0].buffer        = cpPeerHost;
				
			addend[1].header.type   = TLV_TYPE_PEER_PORT;
			addend[1].header.length = sizeof(DWORD);
			addend[1].buffer        = (PUCHAR)&dwPeerPort;

			dprintf( "[UDP] udp_channel_notify. Data on channel=0x%08X, read %d bytes from %s:%d", ctx->sock.channel, dwBytesRead, cpPeerHost, ntohs( from.sin_port ) );

			channel_write( ctx->sock.channel, ctx->sock.remote, addend, 2, bBuffer, dwBytesRead, NULL );
		}

	} while( 0 );

	return ERROR_SUCCESS;
}

/*
 * Bring down a UDP channel an free up the context.
 */
DWORD udp_channel_close( Channel * channel, Packet * request, LPVOID context )
{
	UdpClientContext * ctx = (UdpClientContext *)context;

	do
	{
		dprintf( "[UDP] udp_channel_close. channel=0x%08X, ctx=0x%08X", channel, ctx );

		if( !ctx )
			break;
	
		// Set the context channel to NULL so we don't try to close the
		// channel (since it's already being closed)
		ctx->sock.channel = NULL;

		// Free the context
		free_udp_context( ctx );

		// Set the native channel operations context to NULL
		channel_set_native_io_context( channel, NULL );

	} while( 0 );

	return ERROR_SUCCESS;
}

/*
 * Create a new UDP socket channel, optionally bound to a local address/port and optionaly specify 
 * a remote peer host/port for future writes.
 */
DWORD request_net_udp_channel_open( Remote * remote, Packet * packet )
{
	DWORD dwResult           = ERROR_SUCCESS;
	UdpClientContext * ctx   = NULL;
	Packet * response        = NULL;
	char * lhost             = NULL;
	char * phost             = NULL;
	SOCKADDR_IN saddr        = {0};
	DatagramChannelOps chops = {0};

	do
	{
		response = packet_create_response( packet );
		if( !response )
			BREAK_WITH_ERROR( "[UDP] request_net_udp_channel_open. response == NULL", ERROR_NOT_ENOUGH_MEMORY );
		
		ctx = (UdpClientContext *)malloc( sizeof(UdpClientContext) );
		if( !ctx )
			BREAK_WITH_ERROR( "[UDP] request_net_udp_channel_open. ctx == NULL", ERROR_NOT_ENOUGH_MEMORY );

		memset( ctx, 0, sizeof(UdpClientContext) );
		
		ctx->sock.remote = remote;

		ctx->localport = (USHORT)( packet_get_tlv_value_uint( packet, TLV_TYPE_LOCAL_PORT ) & 0xFFFF );
		if( !ctx->localport )
			ctx->localport = 0;

		ctx->peerport = (USHORT)( packet_get_tlv_value_uint( packet, TLV_TYPE_PEER_PORT ) & 0xFFFF );
		if( !ctx->peerport )
			ctx->peerport = 0;

		lhost = packet_get_tlv_value_string( packet, TLV_TYPE_LOCAL_HOST );
		if( lhost )
			ctx->localhost.s_addr = inet_addr( lhost );
		else
			ctx->localhost.s_addr = INADDR_ANY;

		phost = packet_get_tlv_value_string( packet, TLV_TYPE_PEER_HOST );
		if( phost )
		{
			dprintf( "[UDP] request_net_udp_channel_open. phost=%s", phost );
			ctx->peerhost.s_addr = inet_addr( phost );
		}

		ctx->sock.fd = WSASocket( AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, 0 );
		if( ctx->sock.fd == INVALID_SOCKET )
			BREAK_ON_WSAERROR( "[UDP] request_net_udp_channel_open. WSASocket failed" );

		saddr.sin_family      = AF_INET;
		saddr.sin_port        = htons( ctx->localport );
		saddr.sin_addr.s_addr = ctx->localhost.s_addr;

		if( bind( ctx->sock.fd, (SOCKADDR *)&saddr, sizeof(SOCKADDR_IN) ) == SOCKET_ERROR )
			BREAK_ON_WSAERROR( "[UDP] request_net_udp_channel_open. bind failed" );
		
		ctx->sock.notify = WSACreateEvent();
		if( ctx->sock.notify == WSA_INVALID_EVENT )
			BREAK_ON_WSAERROR( "[UDP] request_net_udp_channel_open. WSACreateEvent failed" );

		if( WSAEventSelect( ctx->sock.fd, ctx->sock.notify, FD_READ ) == SOCKET_ERROR )
			BREAK_ON_WSAERROR( "[UDP] request_net_udp_channel_open. WSAEventSelect failed" );

		memset( &chops, 0, sizeof(DatagramChannelOps) );
		chops.native.context = ctx;
		chops.native.write   = udp_channel_write;
		chops.native.close   = udp_channel_close;

		ctx->sock.channel = channel_create_datagram( 0, 0, &chops );
		if( !ctx->sock.channel )
			BREAK_WITH_ERROR( "[UDP] request_net_udp_channel_open. channel_create_stream failed", ERROR_INVALID_HANDLE );

		scheduler_insert_waitable( ctx->sock.notify, ctx, (WaitableNotifyRoutine)udp_channel_notify );

		packet_add_tlv_uint( response, TLV_TYPE_CHANNEL_ID, channel_get_id(ctx->sock.channel) );

		dprintf( "[UDP] request_net_udp_channel_open. UDP socket on channel %d (The local specified was %s:%d ) (The peer specified was %s:%d)",  channel_get_id( ctx->sock.channel ), inet_ntoa( ctx->localhost ), ctx->localport, inet_ntoa( ctx->peerhost ), ctx->peerport );

	} while( 0 );

	packet_transmit_response( dwResult, remote, response );

	do
	{
		if( dwResult == ERROR_SUCCESS )
			break;

		if( !ctx )		
			break;

		if( ctx->sock.fd )
			closesocket( ctx->sock.fd );
			
		if( ctx->sock.channel )
			channel_destroy( ctx->sock.channel, packet );

		free( ctx );

	} while( 0 );

	return ERROR_SUCCESS;
}
