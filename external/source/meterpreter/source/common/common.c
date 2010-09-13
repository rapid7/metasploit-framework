#include "common.h"

#ifndef _WIN32

/*
 * If we supply real_dprintf in the common.h, each .o file will have a private copy of that symbol.
 * This leads to bloat. Defining it here means that there will only be a single implementation of it.
 */ 

void real_dprintf(char *format, ...)
{
	va_list args;
	char buffer[1024];
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer)-2, format, args);
	strcat(buffer, "\n");
	va_end(args);
	write(2, buffer, strlen(buffer));
}

#endif
