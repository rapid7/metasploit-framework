#include "common.h"


#ifdef _WIN32
// This function returns a unix timestamp in UTC
int current_unix_timestamp(void) {
	SYSTEMTIME system_time;
	FILETIME file_time;
	ULARGE_INTEGER ularge;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	
	ularge.LowPart = file_time.dwLowDateTime;
	ularge.HighPart = file_time.dwHighDateTime;
	return (long)((ularge.QuadPart - 116444736000000000) / 10000000L);
}
#else

#include <sys/time.h>

// This function returns a unix timestamp in UTC
int current_unix_timestamp(void) {
	struct timeval tv;
	struct timezone tz;

	memset(&tv, 0, sizeof(tv));
	memset(&tz, 0, sizeof(tz));

	gettimeofday(&tv, &tz);
	return (long) tv.tv_usec;
}
#endif

#ifndef _WIN32

int debugging_enabled;

/*
 * If we supply real_dprintf in the common.h, each .o file will have a private copy of that symbol.
 * This leads to bloat. Defining it here means that there will only be a single implementation of it.
 */ 

void real_dprintf(char *filename, int line, const char *function, char *format, ...)
{
	va_list args;
	char buffer[2048];
	int size;
	static int fd;
	int retried = 0;

	filename = basename(filename);
	size = snprintf(buffer, sizeof(buffer), "[%s:%d (%s)] ", filename, line, function);

	va_start(args, format);
	vsnprintf(buffer + size, sizeof(buffer) - size, format, args);
	strcat(buffer, "\n");
	va_end(args);

retry_log:
	if(fd <= 0) {
		char filename[128];
		sprintf(filename, "/tmp/meterpreter.log.%d%s", getpid(), retried ? ".retry" : "" );
		
		fd = open(filename, O_RDWR|O_TRUNC|O_CREAT|O_SYNC, 0644);
		
		if(fd <= 0) return;
	}

	if(write(fd, buffer, strlen(buffer)) == -1 && (errno == EBADF)) {
		fd = -1;
		retried++;
		goto retry_log;
	}
}

void enable_debugging()
{
	debugging_enabled = 1;
}

#endif
