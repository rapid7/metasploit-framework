//===============================================================================================//
#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SESSION_PS_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SESSION_PS_H
//===============================================================================================//
#include "./process/ps.h"

DWORD session_id( DWORD dwProcessId );

DWORD session_activeid();

DWORD session_inject( DWORD dwSessionId, DLL_BUFFER * pDllBuffer, char * cpCommandLine );

//===============================================================================================//
#endif
//===============================================================================================//