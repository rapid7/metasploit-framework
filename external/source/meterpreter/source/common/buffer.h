#ifndef _METERPRETER_LIB_BUFFER_H
#define _METERPRETER_LIB_BUFFER_H

#include "linkage.h"

LINKAGE DWORD buffer_from_file(LPCSTR filePath, PUCHAR *buffer, 
		PULONG length);
LINKAGE DWORD buffer_to_file(LPCSTR filePath, PUCHAR buffer, 
		ULONG length);

#endif
