#ifndef _METERPRETER_LIB_SCHEDULER_H
#define _METERPRETER_LIB_SCHEDULER_H

#include "linkage.h"
#include "remote.h"

typedef DWORD (*WaitableNotifyRoutine)(Remote *remote, LPVOID context);

LINKAGE DWORD scheduler_initialize( Remote * remote );
LINKAGE DWORD scheduler_destroy( VOID );
LINKAGE DWORD scheduler_insert_waitable( HANDLE waitable, LPVOID context, WaitableNotifyRoutine routine );
LINKAGE DWORD scheduler_remove_waitable( HANDLE waitable );
LINKAGE DWORD THREADCALL scheduler_waitable_thread( THREAD * thread );

#endif
