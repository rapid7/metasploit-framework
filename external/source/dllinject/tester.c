#include <windows.h>

__declspec(dllexport) Init(SOCKET fd)
{
	char passphrase[9] = { 0 };

	recv(fd, passphrase, 8, 0);

	MessageBox(NULL, passphrase, "you sent me", MB_OK);

	return 0;
}
