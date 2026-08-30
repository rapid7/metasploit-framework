#include <windows.h>
#include <stdlib.h>
#include "../msfpattern.h"

int main() {
    char *ownme, *next;

	Sleep(10000);
	ownme = (char *) malloc(256);
	next = (char *) malloc(256);
    msf_pattern_create(264, ownme);
    free(next); free(ownme);
	return (0);
}
