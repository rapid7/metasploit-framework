#ifndef _METERPRETER_SOURCE_SERVER_LIBLOADER_H
#define _METERPRETER_SOURCE_SERVER_LIBLOADER_H

void *libloader_load_library_mem(char *buffer, char *bufferLength);
void *libloader_load_library_disk(char *name);
void *libloader_lookup_sym(char *name);

#endif
