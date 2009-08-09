#include "compat_types.h"
#include "dlfcn.h"

#pragma weak dlopenbuf
void *
dlopenbuf(const char *name, int mode, char *buffer, int length)
{

	return (NULL);
}


#pragma weak dlsocket
int
dlsocket(void)
{

	return (-1);
}

