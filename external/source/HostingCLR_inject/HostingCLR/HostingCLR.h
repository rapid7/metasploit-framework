#pragma once
#include <io.h>
#include <stdio.h>
#include <tchar.h>
#include <metahost.h>


#pragma comment(lib, "MSCorEE.lib")

#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")

#define STATUS_SUCCESS 0
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

using namespace mscorlib;

VOID Execute(LPVOID lpPayload);
BOOL FindVersion(void * assembly, int length);
BOOL PatchAmsi();
BOOL ClrIsLoaded(LPCWSTR versione, IEnumUnknown* pEnumerator, LPVOID * pRuntimeInfo);
INT InlinePatch(LPVOID lpFuncAddress, UCHAR * patch, int patchsize);
