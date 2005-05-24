#include "metcli.h"

extern VOID remote_register_core_dispatch_routines();
extern VOID remote_deregister_core_dispatch_routines();

HANDLE clientLock = NULL;

/*
 * Entry point for the client
 */
int main(int argc, char **argv)
{
	struct sockaddr_in s;
	Remote *remote = NULL;
	SOCKET cli;
	WSADATA data;

	srand(time(NULL));

	WSAStartup(0x0202, &data);

	if (argc < 3)
	{
		printf("Usage: %s <host> <port>\n", argv[0]);
		return 0;
	}

	do
	{
		if ((cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			fprintf(stderr, "listen: %lu\n", GetLastError());
			break;
		}

		s.sin_family      = AF_INET;
		s.sin_port        = htons((SHORT)atoi(argv[2]));
		s.sin_addr.s_addr = inet_addr(argv[1]);

		printf("Connecting to %s:%d...\n", argv[1], atoi(argv[2]));

		if (connect(cli, (struct sockaddr *)&s, sizeof(s)) < 0)
		{
			fprintf(stderr, "connect: %lu\n", GetLastError());
			break;
		}

		printf("Initialized with server fd %lu.\n", cli);

		if (!(remote = remote_allocate(cli)))
		{
			fprintf(stderr, "remote_allocate: %lu\n", GetLastError());
			break;
		}

		// Initialize the console display
		console_initialize(remote);

		// Register core remote dispatch routines
		remote_register_core_dispatch_routines();

		// Process commands
		console_process_commands(remote);
	
		// Deregister core remote dispatch routines
		remote_deregister_core_dispatch_routines();

	} while (0);

	return 0;
}

/*
 * Initializes the global client lock
 */
VOID client_init_lock()
{
	clientLock = CreateMutex(NULL, FALSE, NULL);
}

/*
 * Acquires the global client lock
 */
VOID client_acquire_lock()
{
	WaitForSingleObjectEx(clientLock, INFINITE, FALSE);
}

/*
 * Releases the global client lock
 */
VOID client_release_lock()
{
	ReleaseMutex(clientLock);
}
