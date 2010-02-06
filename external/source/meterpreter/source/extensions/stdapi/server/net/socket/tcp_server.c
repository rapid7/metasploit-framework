#include "precomp.h"
#include "tcp.h"

/*
 * Deallocates and cleans up the attributes of a tcp server socket context
 */
VOID free_tcp_server_context( TcpServerContext * ctx )
{
	do
	{
		if( !ctx )
			break;

		dprintf( "[TCP-SERVER] free_tcp_server_context. ctx=0x%08X", ctx );

		if( ctx->fd )
		{
			closesocket( ctx->fd );
			ctx->fd = 0;
		}
		
		if( ctx->channel )
		{
			channel_close( ctx->channel, ctx->remote, NULL, 0, NULL );
			ctx->channel = NULL;
		}

		if( ctx->notify )
		{
			scheduler_remove_waitable( ctx->notify );
			ctx->notify = NULL;
		}

		free( ctx );

	} while( 0 );
}

/*
 * Closes the server socket and brings down the client connections.
 */
DWORD tcp_channel_server_close( Channel * channel, Packet * request, LPVOID context )
{
	TcpServerContext * ctx = (TcpServerContext *)context;

	do
	{
		dprintf( "[TCP-SERVER] tcp_channel_server_close. channel=0x%08X, ctx=0x%08X", channel, ctx );

		if( !ctx )
			break;
	
		// Set the context channel to NULL so we don't try to close the
		// channel (since it's already being closed)
		ctx->channel = NULL;

		// Free the context
		free_tcp_server_context( ctx );

		// Set the native channel operations context to NULL
		channel_set_native_io_context( channel, NULL );

	} while( 0 );

	return ERROR_SUCCESS;
}

/*
 * Create a TCP client channel from a socket.
 */
TcpClientContext * tcp_channel_server_create_client( TcpServerContext * serverctx, SOCKET sock )
{
	DWORD dwResult               = ERROR_SUCCESS;
	TcpClientContext * clientctx = NULL;
	StreamChannelOps chops       = {0};

	do
	{
		if( !serverctx )
			BREAK_WITH_ERROR( "[TCP-SERVER] tcp_channel_server_create_client. serverctx == NULL", ERROR_INVALID_HANDLE );

		clientctx = (TcpClientContext *)malloc( sizeof(TcpClientContext) );
		if( !clientctx )
			BREAK_WITH_ERROR( "[TCP-SERVER] tcp_channel_server_create_client. clientctx == NULL", ERROR_NOT_ENOUGH_MEMORY );

		memset( clientctx, 0, sizeof(TcpClientContext) );

		clientctx->remote = serverctx->remote;
		clientctx->fd     = sock;

		clientctx->notify = WSACreateEvent();
		if( clientctx->notify == WSA_INVALID_EVENT )
			BREAK_ON_WSAERROR( "[TCP-SERVER] tcp_channel_server_create_client. WSACreateEvent failed" );

		if( WSAEventSelect( clientctx->fd, clientctx->notify, FD_READ|FD_CLOSE ) == SOCKET_ERROR )
			BREAK_ON_WSAERROR( "[TCP-SERVER] tcp_channel_server_create_client. WSAEventSelect failed" );

		memset( &chops, 0, sizeof(StreamChannelOps) );

		chops.native.context = clientctx;
		chops.native.write   = tcp_channel_client_write;
		chops.native.close   = tcp_channel_client_close;
	
		clientctx->channel = channel_create_stream( 0, 0, &chops );
		if( !clientctx->channel )
			BREAK_WITH_ERROR( "[TCP-SERVER] tcp_channel_server_create_client. clientctx->channel == NULL", ERROR_INVALID_HANDLE );

		dwResult = scheduler_insert_waitable( clientctx->notify, clientctx, (WaitableNotifyRoutine)tcp_channel_client_local_notify );

	} while( 0 );

	if( dwResult != ERROR_SUCCESS )
	{
		if( clientctx )
		{
			free( clientctx );
			clientctx = NULL;
		}
	}

	return clientctx;
}

/*
 * Notify routine for a tcp server channel to pick up its new client connections.
 */
DWORD tcp_channel_server_notify( Remote * remote, TcpServerContext * serverctx )
{
	DWORD dwResult               = ERROR_SUCCESS;
	TcpClientContext * clientctx = NULL;
	Packet * request             = NULL;
	SOCKADDR_IN clientaddr       = {0};
	SOCKADDR_IN serveraddr       = {0};
	SOCKET sock                  = 0;
	DWORD size                   = 0;
	char * localhost             = NULL;
	char * peerhost              = NULL;
	int localport                = 0;
	int peerport                 = 0;

	do
	{
		if( !serverctx )
			BREAK_WITH_ERROR( "[TCP-SERVER] tcp_channel_server_notify. serverctx == NULL", ERROR_INVALID_HANDLE );

		ResetEvent( serverctx->notify );

		size = sizeof(SOCKADDR);

		sock = accept( serverctx->fd, (SOCKADDR *)&clientaddr, &size );
		if( sock == INVALID_SOCKET )
		{
			if( WSAGetLastError() == WSAEWOULDBLOCK )
			{
				Sleep( 100 );
				break;
			}

			BREAK_ON_WSAERROR( "[TCP-SERVER] tcp_channel_server_notify. accept failed" );
		}

		dprintf( "[TCP-SERVER] tcp_channel_server_notify. Got new client connection on channel %d. sock=%d", channel_get_id(serverctx->channel), sock );

		clientctx = tcp_channel_server_create_client( serverctx, sock );
		if( !clientctx )
			BREAK_WITH_ERROR( "[TCP-SERVER] tcp_channel_server_notify. clientctx == NULL", ERROR_INVALID_HANDLE );
		
		size = sizeof(SOCKADDR);

		if( getsockname( serverctx->fd, (SOCKADDR *)&serveraddr, &size ) == SOCKET_ERROR )
			BREAK_ON_WSAERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. getsockname failed" );

		localhost = inet_ntoa( serveraddr.sin_addr );
		if( !localhost )
			localhost = "";

		localport = ntohs( serveraddr.sin_port );

		peerhost = inet_ntoa( clientaddr.sin_addr );
		if( !peerhost )
			peerhost = "";

		peerport = ntohs( clientaddr.sin_port );
		
		dprintf( "[TCP-SERVER] tcp_channel_server_notify. New connection %s:%d <- %s:%d", localhost, localport, peerhost, peerport );

		request = packet_create( PACKET_TLV_TYPE_REQUEST, "tcp_channel_open" );
		if( !request )
			BREAK_WITH_ERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. packet_create failed", ERROR_INVALID_HANDLE );
		
		packet_add_tlv_uint(   request, TLV_TYPE_CHANNEL_ID,       channel_get_id(clientctx->channel) );
		packet_add_tlv_uint(   request, TLV_TYPE_CHANNEL_PARENTID, channel_get_id(serverctx->channel) );
		packet_add_tlv_string( request, TLV_TYPE_LOCAL_HOST,       localhost );
		packet_add_tlv_uint(   request, TLV_TYPE_LOCAL_PORT,       localport );
		packet_add_tlv_string( request, TLV_TYPE_PEER_HOST,        peerhost );
		packet_add_tlv_uint(   request, TLV_TYPE_PEER_PORT,        peerport );

		dwResult = packet_transmit( serverctx->remote, request, NULL );

	} while( 0 );

	return dwResult;
}

/*
 * Allocates a streaming TCP server channel
 */
DWORD request_net_tcp_server_channel_open( Remote * remote, Packet * packet )
{
	DWORD dwResult         = ERROR_SUCCESS;
	TcpServerContext * ctx = NULL;
	Packet * response      = NULL;
	char * lhost           = NULL;
	SOCKADDR_IN saddr      = {0};
	StreamChannelOps chops = {0};
	USHORT lport           = 0;

	do
	{
		response = packet_create_response( packet );
		if( !response )
			BREAK_WITH_ERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. response == NULL", ERROR_NOT_ENOUGH_MEMORY );
		
		ctx = (TcpServerContext *)malloc( sizeof(TcpServerContext) );
		if( !ctx )
			BREAK_WITH_ERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. ctx == NULL", ERROR_NOT_ENOUGH_MEMORY );

		memset( ctx, 0, sizeof(TcpServerContext) );
		
		ctx->remote = remote;

		lport = (USHORT)( packet_get_tlv_value_uint( packet, TLV_TYPE_LOCAL_PORT ) & 0xFFFF );
		if( !lport )
			BREAK_WITH_ERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. lport == NULL", ERROR_INVALID_HANDLE );

		lhost = packet_get_tlv_value_string( packet, TLV_TYPE_LOCAL_HOST );
		if( !lhost )
			lhost = "0.0.0.0";

		ctx->fd = WSASocket( AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0 );
		if( ctx->fd == INVALID_SOCKET )
			BREAK_ON_WSAERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. WSASocket failed" );

		saddr.sin_family      = AF_INET;
		saddr.sin_port        = htons( lport );
		saddr.sin_addr.s_addr = inet_addr( lhost );

		if( bind( ctx->fd, (SOCKADDR *)&saddr, sizeof(SOCKADDR) ) == SOCKET_ERROR )
			BREAK_ON_WSAERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. bind failed" );

		if( listen( ctx->fd, SOMAXCONN ) == SOCKET_ERROR )
			BREAK_ON_WSAERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. listen failed" );
		
		ctx->notify = WSACreateEvent();
		if( ctx->notify == WSA_INVALID_EVENT )
			BREAK_ON_WSAERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. WSACreateEvent failed" );

		if( WSAEventSelect( ctx->fd, ctx->notify, FD_ACCEPT ) == SOCKET_ERROR )
			BREAK_ON_WSAERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. WSAEventSelect failed" );

		memset( &chops, 0, sizeof(StreamChannelOps) );
		chops.native.context = ctx;
		chops.native.close   = tcp_channel_server_close;

		ctx->channel = channel_create_stream( 0, CHANNEL_FLAG_SYNCHRONOUS, &chops );
		if( !ctx->channel )
			BREAK_WITH_ERROR( "[TCP-SERVER] request_net_tcp_server_channel_open. channel_create_stream failed", ERROR_INVALID_HANDLE );

		scheduler_insert_waitable( ctx->notify, ctx, (WaitableNotifyRoutine)tcp_channel_server_notify );

		packet_add_tlv_uint( response, TLV_TYPE_CHANNEL_ID, channel_get_id(ctx->channel) );

		dprintf( "[TCP-SERVER] request_net_tcp_server_channel_open. tcp server %s:%d on channel %d", lhost, lport, channel_get_id(ctx->channel) );

	} while( 0 );

	packet_transmit_response( dwResult, remote, response );

	do
	{
		if( dwResult == ERROR_SUCCESS )
			break;

		if( !ctx )		
			break;

		if( ctx->fd )
			closesocket( ctx->fd );
			
		if( ctx->channel )
			channel_destroy( ctx->channel, packet );

		free( ctx );

	} while( 0 );

	return ERROR_SUCCESS;
}
