#include "../../common/common.h"

#include <sys/errno.h>
#include <fcntl.h>

/*
 * trivial example to test loading functionality
 */
int
InitServerExtension(Remote *remote)
{
	char *buf = "Veni Vedi Vici!\n";
	int fd;

	if ((fd = open("/tmp/meterpreter.txt", O_CREAT|O_WRONLY|O_TRUNC, 0200)) < 0)
		return (errno);

	write(fd, buf, strlen(buf));
	close(fd);
}
