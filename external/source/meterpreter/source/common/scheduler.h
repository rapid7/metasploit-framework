#ifndef _METERPRETER_LIB_SCHEDULER_H
#define _METERPRETER_LIB_SCHEDULER_H

#include "linkage.h"
#include "remote.h"

typedef DWORD (*WaitableNotifyRoutine)(Remote *remote, LPVOID context);

LINKAGE DWORD scheduler_insert_waitable(HANDLE waitable, LPVOID context,
		WaitableNotifyRoutine routine);
LINKAGE DWORD scheduler_remove_waitable(HANDLE waitable);
LINKAGE DWORD scheduler_run(Remote *remote, DWORD timeout);

#endif
