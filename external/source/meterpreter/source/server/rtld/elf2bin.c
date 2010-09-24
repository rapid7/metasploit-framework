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

#include <elf.h>

#define EIGHTMEM (32 * 1024 * 1024)

#define BASE 0x20040000

int main(int argc, char **argv)
{
	int fd;
	struct stat statbuf;
	unsigned char *data; // ELF file
	unsigned char *mapping; // target memory location
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	int i;
	int used = 0;
	unsigned char *source, *dest;
	int len;
	int (*fp)();

	fd = open("msflinker", O_RDONLY);
	if(fd == -1) {
		printf("Failed to open msflinker: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(fstat(fd, &statbuf) == -1) {
		printf("Failed to fstat(fd): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(data == MAP_FAILED) {
		printf("Unable to read ELF file in: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(fd);

	mapping = mmap(BASE, EIGHTMEM, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
	if(mapping == MAP_FAILED) {
		printf("Failed to mmap(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	ehdr = (Elf32_Ehdr *)data;
	phdr = (Elf32_Phdr *)(data + ehdr->e_phoff);
	
	printf("data @ %08x, mapping @ %08x\n", data, mapping);

	for(i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if(phdr->p_type == PT_LOAD) {
			source = data + (phdr->p_offset & ~4095);
			dest = mapping + ((phdr->p_vaddr - BASE) & ~4095);
			len = phdr->p_filesz + (phdr->p_vaddr & 4095);	
			printf("memcpy(%08x, %08x, %08x)\n", dest, source, len);
			memcpy(dest, source, len);
			
			used += (phdr->p_memsz + (phdr->p_vaddr & 4095) + 4095) & ~4095 ;
		}
	}

	fd = open("msflinker.bin", O_RDWR|O_TRUNC|O_CREAT, 0644);
	if(fd == -1) {
		printf("Unable to dump memory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(write(fd, mapping, used) != used) {
		printf("Unable to complete memory dump\n");
		exit(EXIT_FAILURE);
	}

	close(fd);

}
