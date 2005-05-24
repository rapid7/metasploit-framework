#ifndef METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H

#define  _WIN32_WINNT 0x0400
#include "../stdapi.h"
#include <Tlhelp32.h>
#include <iphlpapi.h>

#include "resource/resource.h"
#include "fs/fs.h"
#include "sys/sys.h"
#include "net/net.h"
#include "ui/ui.h"

#define strcasecmp stricmp

extern HMODULE stdapiImageInstance;

#endif
