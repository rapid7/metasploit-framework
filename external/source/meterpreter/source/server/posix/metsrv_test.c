
#define _BSD_SOURCE 1
#define __inet_addr inet_addr

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define __BSD_VISIBLE 1
#include <dlfcn.h>



#define PORT 	31337
#define	ADDR	"127.0.0.1"

extern void metsrv_rtld(int);

int main(int argc, char **argv)
{
	struct sockaddr_in s;
	int (*init)(int, void *) = NULL;
	void *handle;
	int cli;
	in_addr_t addr;
	Dl_info dli;


	bzero(&s, sizeof(s));
	bzero(&dli, sizeof(dli));
	if (argc == 1) {
		printf("expect lib name");
		return (1);
	}
	
	do {
		if ((cli = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			break;
		}
		addr = inet_addr(ADDR);

		s.sin_family      = AF_INET;
		s.sin_port        = htons(PORT);
		s.sin_addr.s_addr = addr;
		printf("connecting to %s:%d...\n", ADDR, PORT);
                if (connect(cli, (struct sockaddr *)&s, sizeof(struct sockaddr)) != 0) { 
		        perror("connect failed"); 
			break;
                }

#ifdef __linux__
		/*
		 * LAZY
		 * GLOBAL , so extensions can use library
		 */
		handle = dlopen(argv[1], RTLD_GLOBAL|RTLD_LAZY);
#else
		handle = dlopen(argv[1], 0444);
#endif
		if (handle == NULL) {
			printf("failed to dlopen(%s)\n", argv[1]);
			perror("giving up");
			return (1);
		}

		init = dlsym(handle, "Init");
		if (init != NULL) {
		  dladdr(init, &dli);
		  init(cli, dli.dli_fbase); 
		}
		
	} while (0);

	return (0);
}


		
