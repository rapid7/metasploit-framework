#ifndef METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H

// sf: Compatability fix for a broken sdk? We get errors in Iphlpapi.h using the latest Windows SDK if we dont do this.
#define  _WIN32_WINNT _WIN32_WINNT_WIN2K

#include "../stdapi.h"
#include <Tlhelp32.h>
#include <iphlpapi.h>

#include "resource/resource.h"
#include "fs/fs.h"
#include "sys/sys.h"
#include "net/net.h"
#include "ui/ui.h"

#include "../../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
#include "../../../ReflectiveDLLInjection/GetProcAddressR.h"
#include "../../../ReflectiveDLLInjection/ReflectiveLoader.h"

#define strcasecmp _stricmp

// declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
extern HINSTANCE hAppInstance;

#endif
