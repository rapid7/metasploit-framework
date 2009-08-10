#include <fcntl.h>
#include "common.h"

DWORD
buffer_from_file(LPCSTR filePath, PUCHAR *buffer, PULONG length)
{
	int fd, res = 0;
	off_t size;	
	char *buf = NULL;
	
	if ((fd = open(filePath, O_RDONLY)) < 0) {
		res = errno;
		return (res);		
	}
	/*
	 * find the end
	 */
	if ((size = lseek(fd, 0, SEEK_END)) < 0) {		
		res = errno;
		goto done;
	}	
	if ((res = lseek(fd, 0, SEEK_SET)) < 0) {		
		res = errno;
		goto done;
	}
	if ((buf = malloc(size)) == NULL) {
		res = ENOMEM;
		goto done;
	}
	if (read(fd, buf, size) < size) {
		res = errno;
		free(buf); 
	}
done:		
	close(fd);	
	if (res == 0) {
		if (buffer)
			*buffer = buf;
		else
			free(buf);		
		if (length)
			*length = size;
	}
	return (res);
}

DWORD
buffer_to_file(LPCSTR filePath, PUCHAR buffer, ULONG length)
{
	int fd, res = 0;
	off_t size;	
	
	if ((fd = open(filePath, O_CREAT|O_TRUNC|O_WRONLY, 0200)) < 0) {
		res = errno;
		return (res);		
	}
	if (write(fd, buffer, length) < length)
		res = errno;	

	close(fd);	
	return (res);
}
