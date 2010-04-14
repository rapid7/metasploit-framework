#include <stdio.h>

#define SCSIZE 8192
char payload[SCSIZE] = "PAYLOAD:";

char comment[512] = "";

int main(int argc, char **argv) {
	(*(void (*)()) payload)();
	return(0);
}
