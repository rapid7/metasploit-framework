#ifndef _METERPRETER_SERVER_METSRV_H
#define _METERPRETER_SERVER_METSRV_H

/*
 * Version number
 *                               v------- major major
 *                                 v----- major minor
 *                                   v--- minor major
 *                                     v- minor minor
 */
#define METSRV_VERSION_NUMBER 0x00000500

#ifdef _WIN32
#define USE_DLL
#endif
#define METERPRETER_EXPORTS
#include "../common/common.h"

#include "remote_dispatch.h"
#include "libloader.h"

#ifdef _WIN32
#include "../ReflectiveDLLInjection/GetProcAddressR.h"
#include "../ReflectiveDLLInjection/LoadLibraryR.h"
#include "../ReflectiveDLLInjection/ReflectiveLoader.h"
#endif

DWORD server_setup(SOCKET fd);

typedef struct _EXTENSION
{
	HMODULE library;
	DWORD (*init)(Remote *remote);
	DWORD (*deinit)(Remote *remote);
} EXTENSION;

#endif
