#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#define PORT 31337

int main(int argc, char **argv)
{
	struct sockaddr_in s;
	DWORD (*init)(SOCKET fd);
	PCHAR dllPath, slash;
	SOCKET srv, cli;
	HMODULE lib;
	WSADATA data;

	WSAStartup(0x0202, &data);

	do
	{
		if (argc == 1)
		{
			printf("need dll path\n");
			break;
		}

		if (!(dllPath = (PCHAR)malloc(strlen(argv[0]+5))))
		{
			fprintf(stderr, "could not duplicate argv\n");
			break;
		}

		printf("loading from %s\n", argv[1]);

		lib = LoadLibrary(argv[1]);

		if ((!lib) ||
		    (!((LPVOID)init = (LPVOID)GetProcAddress(lib, "Init"))))
		{
			fprintf(stderr, "could not load metsrv.dll, %lu\n", GetLastError());
			break;
		}

		if ((srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			fprintf(stderr, "listen: %lu\n", GetLastError());
			break;
		}

		s.sin_family      = AF_INET;
		s.sin_port        = htons(PORT);
		s.sin_addr.s_addr = INADDR_ANY;

		printf("Listening on port %d...\n", PORT);

		if (bind(srv, (struct sockaddr *)&s, sizeof(s)) < 0)
		{
			fprintf(stderr, "bind: %lu\n", GetLastError());
			break;
		}

		if (listen(srv, 1) < 0)
		{
			fprintf(stderr, "listen: %lu\n", GetLastError());
			break;
		}

		if ((cli = accept(srv, NULL, NULL)) < 0)
		{
			fprintf(stderr, "accept: %lu\n", GetLastError());
			break;
		}

		printf("Initialized with client fd %lu.\n", cli);

		init(cli);

	} while (0);

	return 0;
}
