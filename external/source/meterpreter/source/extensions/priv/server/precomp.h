#ifndef METERPRETER_SOURCE_EXTENSION_PRIV_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_PRIV_SERVER_PRECOMP_H

#define  _WIN32_WINNT 0x0400
#include "../priv.h"
#include "passwd.h"
#include "fs.h"

#include "../../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
#include "../../../ReflectiveDLLInjection/GetProcAddressR.h"
#include "../../../ReflectiveDLLInjection/ReflectiveLoader.h"

#define strcasecmp stricmp

// declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
extern HINSTANCE hAppInstance;

#endif
