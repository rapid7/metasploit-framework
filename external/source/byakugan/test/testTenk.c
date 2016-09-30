#include <windows.h>

#define NUMPTRS		10

int main(int argc, char **argv) {
	char	*foo[NUMPTRS];
	int		i;

	Sleep(10000);

	for (i = 0; i < NUMPTRS; i++) {
		foo[i] = malloc(256);
		printf("%d: 0x%08x\n", i, foo[i]);
	}
	__asm {
		int 3
	}
	for (i = 0; i < NUMPTRS; i+=2) {
		free(foo[i]);
	}
	free(foo[1]);
	free(foo[7]);
	free(foo[3]);
	__asm {
		int 3
	}
}
