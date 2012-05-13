#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "mirv.h"
#include <ws2tcpip.h>
#include <winsock2.h>
#include "lua_mirv_extensions.h"
#pragma comment (lib, "Ws2_32.lib")

int l_sendudp (lua_State *L){
	const char *message;
	const char *dest;	
	int port;
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	struct sockaddr_in *RecvAddr;
	int iResult;
	char buf[8192];
	message=luaL_checkstring(L,1);
	dest=luaL_checkstring(L,2);
	port=luaL_checkinteger(L,3);
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != 0) {
		return luaL_error(L,"WSAStartup failed with error: %d\n", iResult);

	}
	ZeroMemory( &hints, sizeof(hints) );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	// Resolve the server address and port
	sprintf(buf,"%i",port);
	iResult = getaddrinfo(dest, buf, &hints, &result);
	if ( iResult != 0 ) {
		WSACleanup();
		return luaL_error(L,"getaddrinfo failed with error: %d\n", iResult);
		
		//return -1;
	}
	ConnectSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ConnectSocket == INVALID_SOCKET) {
		iResult=WSAGetLastError();
		WSACleanup();
		return luaL_error(L,"socket failed with error: %ld\n", iResult);        
	}
	// Attempt to connect to an address until one succeeds
	for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {
		//RecvAddr = (struct sockaddr_in *) ptr->ai_addr;		 
		iResult = sendto(ConnectSocket,
			message, strlen(message), 0, ptr->ai_addr, ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			iResult=WSAGetLastError();
			closesocket(ConnectSocket);
			WSACleanup();
			return luaL_error(L,"sendto failed with error: %d\n", iResult);
			closesocket(ConnectSocket);
			return 0;

		}
	}
	return 0;
}
