#ifndef METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H

#ifdef _WIN32
// sf: Compatability fix for a broken sdk? We get errors in Iphlpapi.h using the latest Windows SDK if we dont do this.
#define  _WIN32_WINNT _WIN32_WINNT_WIN2K

#include <Tlhelp32.h>
#include <iphlpapi.h>

#include "resource/resource.h"
#else
 #include <sys/socket.h>
 #include <sys/stat.h>
 #include <netdb.h>
#endif

#include "../stdapi.h"
#include "fs/fs.h"
#include "sys/sys.h"
#include "net/net.h"
#include "ui/ui.h"

#ifdef _WIN32
 #include "../../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
 #include "../../../ReflectiveDLLInjection/GetProcAddressR.h"
 #include "../../../ReflectiveDLLInjection/ReflectiveLoader.h"
 // declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
 extern HINSTANCE hAppInstance;
#endif

#define strcasecmp _stricmp


#endif
