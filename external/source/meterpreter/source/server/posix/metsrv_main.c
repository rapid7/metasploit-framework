#include "metsrv.h"

#ifdef __linux__
int __isthreaded = 0;

void
_pthread_mutex_lock(void)
{
}

void
_pthread_mutex_unlock(void)
{
	
}


void
_pthread_mutex_trylock(void)
{
}

void
_init_tls(void)
{
	
}


#endif


int
main(int argc, char **argv, char **environ)
{	
	int fd;

	if (argc == 1)
		fd = _dlsocket();
	else {
		printf("argc=%d argv=%p ", argc, argv);
		printf(" name=%s ", argv[0]);
		printf(" fd=%d\n",(int)argv[1]);
		fd = (int)argv[1];
	}

	return server_setup(fd);
}
