//////////////////////////////////////////////////////////////////////////////
//
//  Module Enumeration Functions (modules.cpp of detours.lib)
//
//  Microsoft Research Detours Package, Version 2.1.
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  Module enumeration functions.
//

#include <windows.h>
#if (_MSC_VER < 1310)
#else
#include <strsafe.h>
#endif

//#define DETOUR_DEBUG 1
#define DETOURS_INTERNAL
#include "detours.h"

//////////////////////////////////////////////////////////////////////////////
//
#ifndef _STRSAFE_H_INCLUDED_
static inline HRESULT StringCchLengthA(const char* psz, size_t cchMax, size_t* pcch)
{
    HRESULT hr = S_OK;
    size_t cchMaxPrev = cchMax;

    if (cchMax > 2147483647)
    {
        return ERROR_INVALID_PARAMETER;
    }

    while (cchMax && (*psz != '\0'))
    {
        psz++;
        cchMax--;
    }

    if (cchMax == 0)
    {
        // the string is longer than cchMax
        hr = ERROR_INVALID_PARAMETER;
    }

    if (SUCCEEDED(hr) && pcch)
    {
        *pcch = cchMaxPrev - cchMax;
    }

    return hr;
}


static inline HRESULT StringCchCopyA(char* pszDest, size_t cchDest, const char* pszSrc)
{
    HRESULT hr = S_OK;

    if (cchDest == 0)
    {
        // can not null terminate a zero-byte dest buffer
        hr = ERROR_INVALID_PARAMETER;
    }
    else
    {
        while (cchDest && (*pszSrc != '\0'))
        {
            *pszDest++ = *pszSrc++;
            cchDest--;
        }

        if (cchDest == 0)
        {
            // we are going to truncate pszDest
            pszDest--;
            hr = ERROR_INVALID_PARAMETER;
        }

        *pszDest= '\0';
    }

    return hr;
}

static inline HRESULT StringCchCatA(char* pszDest, size_t cchDest, const char* pszSrc)
{
    HRESULT hr;
    size_t cchDestCurrent;

    if (cchDest > 2147483647)
    {
        return ERROR_INVALID_PARAMETER;
    }

    hr = StringCchLengthA(pszDest, cchDest, &cchDestCurrent);

    if (SUCCEEDED(hr))
    {
        hr = StringCchCopyA(pszDest + cchDestCurrent,
                            cchDest - cchDestCurrent,
                            pszSrc);
    }

    return hr;
}

#endif

//////////////////////////////////////////////////////////////////////////////
//
const GUID DETOUR_EXE_RESTORE_GUID = {
    0x2ed7a3ff, 0x3339, 0x4a8d,
    { 0x80, 0x5c, 0xd4, 0x98, 0x15, 0x3f, 0xc2, 0x8f }};

//////////////////////////////////////////////////////////////////////////////
//
PDETOUR_SYM_INFO DetourLoadImageHlp(VOID)
{
    static DETOUR_SYM_INFO symInfo;
    static PDETOUR_SYM_INFO pSymInfo = NULL;
    static BOOL failed = false;

    if (failed) {
        return NULL;
    }
    if (pSymInfo != NULL) {
        return pSymInfo;
    }

    ZeroMemory(&symInfo, sizeof(symInfo));
    // Create a real handle to the process.
#if 0
    DuplicateHandle(GetCurrentProcess(),
                    GetCurrentProcess(),
                    GetCurrentProcess(),
                    &symInfo.hProcess,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS);
#else
    symInfo.hProcess = GetCurrentProcess();
#endif

    symInfo.hDbgHelp = LoadLibraryA("dbghelp.dll");
    if (symInfo.hDbgHelp == NULL) {
      abort:
        failed = true;
        if (symInfo.hDbgHelp != NULL) {
            FreeLibrary(symInfo.hDbgHelp);
        }
        symInfo.pfImagehlpApiVersionEx = NULL;
        symInfo.pfSymInitialize = NULL;
        symInfo.pfSymSetOptions = NULL;
        symInfo.pfSymGetOptions = NULL;
        symInfo.pfSymLoadModule64 = NULL;
        symInfo.pfSymGetModuleInfo64 = NULL;
        symInfo.pfSymFromName = NULL;
        return NULL;
    }

    symInfo.pfImagehlpApiVersionEx
        = (PF_ImagehlpApiVersionEx)GetProcAddress(symInfo.hDbgHelp,
                                                  "ImagehlpApiVersionEx");
    symInfo.pfSymInitialize
        = (PF_SymInitialize)GetProcAddress(symInfo.hDbgHelp, "SymInitialize");
    symInfo.pfSymSetOptions
        = (PF_SymSetOptions)GetProcAddress(symInfo.hDbgHelp, "SymSetOptions");
    symInfo.pfSymGetOptions
        = (PF_SymGetOptions)GetProcAddress(symInfo.hDbgHelp, "SymGetOptions");
    symInfo.pfSymLoadModule64
        = (PF_SymLoadModule64)GetProcAddress(symInfo.hDbgHelp, "SymLoadModule64");
    symInfo.pfSymGetModuleInfo64
        = (PF_SymGetModuleInfo64)GetProcAddress(symInfo.hDbgHelp, "SymGetModuleInfo64");
    symInfo.pfSymFromName
        = (PF_SymFromName)GetProcAddress(symInfo.hDbgHelp, "SymFromName");

    API_VERSION av;
    ZeroMemory(&av, sizeof(av));
    av.MajorVersion = API_VERSION_NUMBER;

    if (symInfo.pfImagehlpApiVersionEx == NULL ||
        symInfo.pfSymInitialize == NULL ||
        symInfo.pfSymLoadModule64 == NULL ||
        symInfo.pfSymGetModuleInfo64 == NULL ||
        symInfo.pfSymFromName == NULL) {
        goto abort;
    }

    symInfo.pfImagehlpApiVersionEx(&av);
    if (av.MajorVersion < API_VERSION_NUMBER) {
        goto abort;
    }

    if (!symInfo.pfSymInitialize(symInfo.hProcess, NULL, FALSE)) {
        // We won't retry the initialize if it fails.
        goto abort;
    }

    if (symInfo.pfSymGetOptions != NULL && symInfo.pfSymSetOptions != NULL) {
        DWORD dw = symInfo.pfSymGetOptions();

        dw &= ~(SYMOPT_CASE_INSENSITIVE |
                SYMOPT_UNDNAME |
                SYMOPT_DEFERRED_LOADS |
                0);
        dw |= (
#if defined(SYMOPT_EXACT_SYMBOLS)
               SYMOPT_EXACT_SYMBOLS |
#endif
#if defined(SYMOPT_NO_UNQUALIFIED_LOADS)
               SYMOPT_NO_UNQUALIFIED_LOADS |
#endif
               SYMOPT_DEFERRED_LOADS |
#if defined(SYMOPT_FAIL_CRITICAL_ERRORS)
               SYMOPT_FAIL_CRITICAL_ERRORS |
#endif
#if defined(SYMOPT_INCLUDE_32BIT_MODULES)
               SYMOPT_INCLUDE_32BIT_MODULES |
#endif
               0);
        symInfo.pfSymSetOptions(dw);
    }

    pSymInfo = &symInfo;
    return pSymInfo;
}

PVOID WINAPI DetourFindFunction(PCSTR pszModule, PCSTR pszFunction)
{
    /////////////////////////////////////////////// First, try GetProcAddress.
    //
    HMODULE hModule = LoadLibraryA(pszModule);
    if (hModule == NULL) {
        return NULL;
    }

    PBYTE pbCode = (PBYTE)GetProcAddress(hModule, pszFunction);
    if (pbCode) {
        return pbCode;
    }

    ////////////////////////////////////////////////////// Then try ImageHelp.
    //
    DETOUR_TRACE(("DetourFindFunction(%s, %s)\n", pszModule, pszFunction));
    PDETOUR_SYM_INFO pSymInfo = DetourLoadImageHlp();
    if (pSymInfo == NULL) {
        DETOUR_TRACE(("DetourLoadImageHlp failed: %d\n",
                      GetLastError()));
        return NULL;
    }

    if (pSymInfo->pfSymLoadModule64(pSymInfo->hProcess, NULL,
                                    (PCHAR)pszModule, NULL,
                                    (DWORD64)hModule, 0) == 0) {
        DETOUR_TRACE(("SymLoadModule64(%p) failed: %d\n",
                      pSymInfo->hProcess, GetLastError()));
        // We don't stop because some version of dbghelp fail secondary calls.
        //return NULL;
    }

    HRESULT hrRet;
    CHAR szFullName[512];
    IMAGEHLP_MODULE64 modinfo;
    ZeroMemory(&modinfo, sizeof(modinfo));
    modinfo.SizeOfStruct = sizeof(modinfo);
    if (!pSymInfo->pfSymGetModuleInfo64(pSymInfo->hProcess, (DWORD64)hModule, &modinfo)) {
        DETOUR_TRACE(("SymGetModuleInfo64(%p, %p) failed: %d\n",
                      pSymInfo->hProcess, hModule, GetLastError()));
        return NULL;
    }

    hrRet = StringCchCopyA(szFullName, sizeof(szFullName)/sizeof(CHAR), modinfo.ModuleName);
    if (FAILED(hrRet)) {
        DETOUR_TRACE(("StringCchCopyA failed: %08x\n", hrRet));
        return NULL;
    }
    hrRet = StringCchCatA(szFullName, sizeof(szFullName)/sizeof(CHAR), "!");
    if (FAILED(hrRet)) {
        DETOUR_TRACE(("StringCchCatA failed: %08x\n", hrRet));
        return NULL;
    }
    hrRet = StringCchCatA(szFullName, sizeof(szFullName)/sizeof(CHAR), pszFunction);
    if (FAILED(hrRet)) {
        DETOUR_TRACE(("StringCchCatA failed: %08x\n", hrRet));
        return NULL;
    }

    struct CFullSymbol : SYMBOL_INFO {
        CHAR szRestOfName[512];
    } symbol;
    ZeroMemory(&symbol, sizeof(symbol));
    //symbol.ModBase = (ULONG64)hModule;
    symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
#ifdef DBHLPAPI
    symbol.MaxNameLen = sizeof(symbol.szRestOfName)/sizeof(symbol.szRestOfName[0]);
#else
    symbol.MaxNameLength = sizeof(symbol.szRestOfName)/sizeof(symbol.szRestOfName[0]);
#endif

    if (!pSymInfo->pfSymFromName(pSymInfo->hProcess, szFullName, &symbol)) {
        DETOUR_TRACE(("SymFromName(%s) failed: %d\n", szFullName, GetLastError()));
        return NULL;
    }

#ifdef DETOURS_IA64
    // On the IA64, we get a raw code pointer from the symbol engine
    // and have to convert it to a wrapped [code pointer, global pointer].
    //
    PPLABEL_DESCRIPTOR pldEntry = (PPLABEL_DESCRIPTOR)DetourGetEntryPoint(hModule);
    PPLABEL_DESCRIPTOR pldSymbol = new PLABEL_DESCRIPTOR;

    pldSymbol->EntryPoint = symbol.Address;
    pldSymbol->GlobalPointer = pldEntry->GlobalPointer;
    return (PBYTE)pldSymbol;
#else
    return (PBYTE)symbol.Address;
#endif
}

//////////////////////////////////////////////////// Module Image Functions.
//
HMODULE WINAPI DetourEnumerateModules(HMODULE hModuleLast)
{
    PBYTE pbLast;

    if (hModuleLast == NULL) {
        pbLast = (PBYTE)0x10000;
    }
    else {
        pbLast = (PBYTE)hModuleLast + 0x10000;
    }

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));

    // Find the next memory region that contains a mapped PE image.
    //
    for (;; pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {
        if (VirtualQuery((PVOID)pbLast, &mbi, sizeof(mbi)) <= 0) {
            break;
        }

        // Skip uncommitted regions and guard pages.
        //
        if ((mbi.State != MEM_COMMIT) || (mbi.Protect & PAGE_GUARD)) {
            continue;
        }

        __try {
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbLast;
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                continue;
            }

            PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
                                                              pDosHeader->e_lfanew);
            if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
                continue;
            }

            return (HMODULE)pDosHeader;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
    }
    return NULL;
}

PVOID WINAPI DetourGetEntryPoint(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (hModule == NULL) {
        pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    }

    __try {
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return NULL;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
                                                          pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return NULL;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return NULL;
        }
        SetLastError(NO_ERROR);
        return ((PBYTE)pDosHeader) +
            pNtHeader->OptionalHeader.AddressOfEntryPoint;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_EXE_MARKED_INVALID);
        return NULL;
    }
}

ULONG WINAPI DetourGetModuleSize(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (hModule == NULL) {
        pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    }

    __try {
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return NULL;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
                                                          pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return NULL;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return NULL;
        }
        SetLastError(NO_ERROR);

        return (pNtHeader->OptionalHeader.SizeOfImage);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_EXE_MARKED_INVALID);
        return NULL;
    }
}

static inline PBYTE RvaAdjust(PIMAGE_DOS_HEADER pDosHeader, DWORD raddr)
{
    if (raddr != NULL) {
        return ((PBYTE)pDosHeader) + raddr;
    }
    return NULL;
}

BOOL WINAPI DetourEnumerateExports(HMODULE hModule,
                                   PVOID pContext,
                                   PF_DETOUR_ENUMERATE_EXPORT_CALLBACK pfExport)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (hModule == NULL) {
        pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    }

    __try {
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return NULL;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
                                                          pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return FALSE;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return FALSE;
        }

        PIMAGE_EXPORT_DIRECTORY pExportDir
            = (PIMAGE_EXPORT_DIRECTORY)
            RvaAdjust(pDosHeader,
                      pNtHeader->OptionalHeader
                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        if (pExportDir == NULL) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return FALSE;
        }

        PDWORD pdwFunctions = (PDWORD)RvaAdjust(pDosHeader, pExportDir->AddressOfFunctions);
        PDWORD pdwNames = (PDWORD)RvaAdjust(pDosHeader, pExportDir->AddressOfNames);
        PWORD pwOrdinals = (PWORD)RvaAdjust(pDosHeader, pExportDir->AddressOfNameOrdinals);

        for (DWORD nFunc = 0; nFunc < pExportDir->NumberOfFunctions; nFunc++) {
            PBYTE pbCode = (pdwFunctions != NULL)
                ? (PBYTE)RvaAdjust(pDosHeader, pdwFunctions[nFunc]) : NULL;
            PCHAR pszName = NULL;
            for (DWORD n = 0; n < pExportDir->NumberOfNames; n++) {
                if (pwOrdinals[n] == nFunc) {
                    pszName = (pdwNames != NULL)
                        ? (PCHAR)RvaAdjust(pDosHeader, pdwNames[n]) : NULL;
                    break;
                }
            }
            ULONG nOrdinal = pExportDir->Base + nFunc;

            if (!pfExport(pContext, nOrdinal, pszName, pbCode)) {
                break;
            }
        }
        SetLastError(NO_ERROR);
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_EXE_MARKED_INVALID);
        return NULL;
    }
}

static PDETOUR_LOADED_BINARY WINAPI GetPayloadSectionFromModule(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (hModule == NULL) {
        pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    }

    __try {
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return NULL;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
                                                          pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return NULL;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return NULL;
        }

        PIMAGE_SECTION_HEADER pSectionHeaders
            = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeader
                                      + sizeof(pNtHeader->Signature)
                                      + sizeof(pNtHeader->FileHeader)
                                      + pNtHeader->FileHeader.SizeOfOptionalHeader);

        for (DWORD n = 0; n < pNtHeader->FileHeader.NumberOfSections; n++) {
            if (strcmp((PCHAR)pSectionHeaders[n].Name, ".detour") == 0) {
                if (pSectionHeaders[n].VirtualAddress == 0 ||
                    pSectionHeaders[n].SizeOfRawData == 0) {

                    break;
                }

                PBYTE pbData = (PBYTE)pDosHeader + pSectionHeaders[n].VirtualAddress;
                DETOUR_SECTION_HEADER *pHeader = (DETOUR_SECTION_HEADER *)pbData;
                if (pHeader->cbHeaderSize < sizeof(DETOUR_SECTION_HEADER) ||
                    pHeader->nSignature != DETOUR_SECTION_HEADER_SIGNATURE) {

                    break;
                }

                if (pHeader->nDataOffset == 0) {
                    pHeader->nDataOffset = pHeader->cbHeaderSize;
                }
                SetLastError(NO_ERROR);
                return (PBYTE)pHeader;
            }
        }
        SetLastError(ERROR_EXE_MARKED_INVALID);
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_EXE_MARKED_INVALID);
        return NULL;
    }
}

DWORD WINAPI DetourGetSizeOfPayloads(HMODULE hModule)
{
    PDETOUR_LOADED_BINARY pBinary = GetPayloadSectionFromModule(hModule);
    if (pBinary == NULL) {
        // Error set by GetPayloadSectonFromModule.
        return 0;
    }

    __try {
        DETOUR_SECTION_HEADER *pHeader = (DETOUR_SECTION_HEADER *)pBinary;
        if (pHeader->cbHeaderSize < sizeof(DETOUR_SECTION_HEADER) ||
            pHeader->nSignature != DETOUR_SECTION_HEADER_SIGNATURE) {

            SetLastError(ERROR_INVALID_HANDLE);
            return 0;
        }
        SetLastError(NO_ERROR);
        return pHeader->cbDataSize;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
}

PVOID WINAPI DetourFindPayload(HMODULE hModule, REFGUID rguid, DWORD * pcbData)
{
    PBYTE pbData = NULL;
    if (pcbData) {
        *pcbData = 0;
    }

    PDETOUR_LOADED_BINARY pBinary = GetPayloadSectionFromModule(hModule);
    if (pBinary == NULL) {
        // Error set by GetPayloadSectonFromModule.
        return NULL;
    }

    __try {
        DETOUR_SECTION_HEADER *pHeader = (DETOUR_SECTION_HEADER *)pBinary;
        if (pHeader->cbHeaderSize < sizeof(DETOUR_SECTION_HEADER) ||
            pHeader->nSignature != DETOUR_SECTION_HEADER_SIGNATURE) {

            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return NULL;
        }

        PBYTE pbBeg = ((PBYTE)pHeader) + pHeader->nDataOffset;
        PBYTE pbEnd = ((PBYTE)pHeader) + pHeader->cbDataSize;

        for (pbData = pbBeg; pbData < pbEnd;) {
            DETOUR_SECTION_RECORD *pSection = (DETOUR_SECTION_RECORD *)pbData;

            if (pSection->guid.Data1 == rguid.Data1 &&
                pSection->guid.Data2 == rguid.Data2 &&
                pSection->guid.Data3 == rguid.Data3 &&
                pSection->guid.Data4[0] == rguid.Data4[0] &&
                pSection->guid.Data4[1] == rguid.Data4[1] &&
                pSection->guid.Data4[2] == rguid.Data4[2] &&
                pSection->guid.Data4[3] == rguid.Data4[3] &&
                pSection->guid.Data4[4] == rguid.Data4[4] &&
                pSection->guid.Data4[5] == rguid.Data4[5] &&
                pSection->guid.Data4[6] == rguid.Data4[6] &&
                pSection->guid.Data4[7] == rguid.Data4[7]) {

                if (pcbData) {
                    *pcbData = pSection->cbBytes - sizeof(*pSection);
                    SetLastError(NO_ERROR);
                    return (PBYTE)(pSection + 1);
                }
            }

            pbData = (PBYTE)pSection + pSection->cbBytes;
        }
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
}

BOOL WINAPI DetourRestoreAfterWithEx(PVOID pvData, DWORD cbData)
{
    PDETOUR_EXE_RESTORE pder = (PDETOUR_EXE_RESTORE)pvData;

    if (pder->cb != sizeof(*pder) || pder->cb > cbData) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    DWORD dwPermIdh;
    DWORD dwPermInh;
    DWORD dwPermClr;
    DWORD dwOld;
    BOOL fSucceeded = FALSE;

    if (!VirtualProtect(pder->pidh, sizeof(pder->idh),
                        PAGE_EXECUTE_READWRITE, &dwPermIdh)) {
        goto end0;
    }
    if (!VirtualProtect(pder->pinh, sizeof(pder->inh),
                        PAGE_EXECUTE_READWRITE, &dwPermInh)) {
        goto end1;
    }
    if (pder->pclrFlags != NULL) {
        if (!VirtualProtect(pder->pclrFlags, sizeof(pder->clrFlags),
                            PAGE_EXECUTE_READWRITE, &dwPermClr)) {
            goto end2;
        }
    }

    CopyMemory(pder->pidh, &pder->idh, sizeof(pder->idh));
    CopyMemory(pder->pinh, &pder->inh, sizeof(pder->inh));

    if (pder->pclrFlags != NULL) {
        CopyMemory(pder->pclrFlags, &pder->clrFlags, sizeof(pder->clrFlags));
    }
    fSucceeded = TRUE;

    if (pder->pclrFlags != NULL) {
        VirtualProtect(pder->pclrFlags, sizeof(pder->clrFlags), dwPermIdh, &dwOld);
    }
  end2:
    VirtualProtect(pder->pinh, sizeof(pder->inh), dwPermInh, &dwOld);
  end1:
    VirtualProtect(pder->pidh, sizeof(pder->idh), dwPermIdh, &dwOld);
  end0:
    return fSucceeded;
}

BOOL WINAPI DetourRestoreAfterWith()
{
    for (HMODULE hMod = NULL; (hMod = DetourEnumerateModules(hMod)) != NULL;) {
        PVOID pvData;
        DWORD cbData;

        pvData = DetourFindPayload(hMod, DETOUR_EXE_RESTORE_GUID, &cbData);

        if (pvData == NULL || cbData == 0) {
            continue;
        }

        return DetourRestoreAfterWithEx(pvData, cbData);
    }
    SetLastError(ERROR_MOD_NOT_FOUND);
    return FALSE;
}

//  End of File
