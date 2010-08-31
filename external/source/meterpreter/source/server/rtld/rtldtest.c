#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

unsigned char *mapping;

int main(int argc, char **argv)
{
	int fd;
	struct stat statbuf;


	int (*fp)();

	fd = open("msflinker.bin", O_RDONLY);
	if(fd == -1) {
		printf("Failed to open msflinker: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(fstat(fd, &statbuf) == -1) {
		printf("Failed to fstat(fd): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// mapping = mmap(0x90040000, statbuf.st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	mapping = mmap(0x90040000, statbuf.st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_PRIVATE, fd, 0);
	if(mapping == MAP_FAILED || mapping != 0x90040000) {
		printf("Failed to mmap(): %s (%08x) \n", strerror(errno), mapping);
		exit(EXIT_FAILURE);
	}

	fp = (unsigned int)EP;
	printf("entry point ahoy @ %08x!\n", fp); fflush(stdout);
	fp(5);
	printf("entry point retured\n");
}
