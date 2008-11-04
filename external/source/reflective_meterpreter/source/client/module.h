#ifndef _METERPRETER_SOURCE_CLIENT_MODULE_H
#define _METERPRETER_SOURCE_CLIENT_MODULE_H

DWORD module_load_client(Remote *remote, LPCSTR name, LPCSTR path);
DWORD module_enumerate_client(DWORD index, LPCSTR *name);
DWORD module_unload_client(Remote *remote, LPCSTR name);

#endif
