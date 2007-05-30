#include <stdio.h>
#include <string.h>
#include <errno.h>
//#include <windows.h>

#if defined _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h> 
#endif

#define SERVER_PORT    5432
#define MAX_PENDING     1


int ehlo, from;

/* Main function */

void Runner(int new_s);

int main(int argc, char **argv) {
	struct 			sockaddr_in sin;
	char 			buf[8092], *ptr;
	int 			c, i, len, port;
	int 			s, new_s, bytes;
#if defined _WIN32
	int 			wsaret;
	WSADATA 		wsaData;
#endif
	int 			(*funct)();


	/* Command line parameters */
	if (argv[1])
		port = atoi(argv[1]);
	else
		port = SERVER_PORT;

#if defined _WIN32
	/* Initialize winsock */
	wsaret = WSAStartup(0x101, &wsaData);
	if(wsaret != 0)
		return (0);

	/* Create a socket */
	if ((s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)) < 0) {
		fprintf(stderr, "%s: WSASocket - %s\n", argv[0], strerror(errno));
		exit(1);
	}
#else
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s: socket - %s\n", argv[0], strerror(errno));
		exit(1);
	}

#endif

	/* Initialize the addres data structure */
	memset((void *)&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);

	/* Bind an address to the socket */
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		fprintf(stderr, "%s: bind - %s\n", argv[0], strerror(errno));
		exit(1);
	}

	/* Set the length of the listen queue */
	if (listen(s, MAX_PENDING) < 0) {
		fprintf(stderr, "%s: listen - %s\n", argv[0], strerror(errno));
		exit(1);
	}
	

	while (1)
	{
		__try
		{
			len = sizeof(sin);
			new_s = accept(s, (struct sockaddr *)&sin, &len);

			CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Runner, (void *)new_s, 0, NULL));

		} __except(EXCEPTION_EXECUTE_HANDLER)
		{
			fprintf(stderr, "Got exception: %lu\n", GetExceptionCode());
		}
	}
	
	return (0);

}

void RunnerStuff(int sock)
{
	char buf[64];
	int 			bytes;

	bytes = recv(sock, buf, 3048, 0);

	printf("recv'd %d\n", bytes);
}

void Runner(int new_s)
{
	char 			buf[4096];

	RunnerStuff(new_s);

	fprintf(stderr, "done");
}
