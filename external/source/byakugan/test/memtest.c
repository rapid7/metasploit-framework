#include <stdio.h>
#include <windows.h>


#define TESTSIZE    35

void main() {
    void    *foo[TESTSIZE];
    int     i;

	Sleep(10000);

    for(i=0;i<TESTSIZE;i++) {
        foo[i] = malloc(0x100);
        printf("Alloc'd %d: 0x%08x\n", i+1, foo[i]);
    }

	for(i=10; i<20; i++) {
		free(foo[i]);
		printf("Free'd %d: 0x%08x\n", i+1, foo[i]);
	}

	for(i=10;i<13;i++) {
		foo[i] = malloc(0x200);
        printf("Alloc'd %d: 0x%08x\n", i+1, foo[i]);
	}
	Sleep(10000);
	__asm {
		int 3
	}


    return;
}
