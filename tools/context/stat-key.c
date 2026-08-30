/*
 * Given a filename, outputs a 32bit key for use in 
 * context keyed payload encoding. The key is derived from
 * XOR-ing the st_size and st_mtime fields of the
 * relevant struct stat for this file.
 *
 * Author: Dimitris Glynos <dimitris at census-labs.com>
 */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	char *filename;
	struct stat stat_buf;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <filename>\n", argv[0]);
		return 1;
	}

	filename = argv[1];
	
	if (stat(filename, &stat_buf) == -1) {
		perror("error while stat(2)-ing file");
		return 1;
	} 	

	printf("%#.8lx\n", stat_buf.st_mtime ^ stat_buf.st_size);
	return 0;
}
