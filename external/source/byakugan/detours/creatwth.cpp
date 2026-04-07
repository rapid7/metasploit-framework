//////////////////////////////////////////////////////////////////////////////
//
//  Create a process with a DLL (creatwth.cpp of detours.lib)
//
//  Microsoft Research Detours Package, Version 2.1.
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

#include <windows.h>
#include <stddef.h>
#if (_MSC_VER < 1299)
typedef DWORD DWORD_PTR;
#endif
#if (_MSC_VER < 1310)
#else
#include <strsafe.h>
#endif

//#define DETOUR_DEBUG 1
#define DETOURS_INTERNAL

#include "detours.h"

#define IMPORT_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
#define BOUND_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
#define CLR_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
#define IAT_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]

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
static WORD detour_sum_minus(WORD wSum, WORD wMinus)
{
    wSum = (WORD)(wSum - ((wSum < wMinus) ? 1 : 0));
    wSum = (WORD)(wSum - wMinus);
    return wSum;
}

static WORD detour_sum_done(DWORD PartialSum)
{
    // Fold final carry into a single word result and return the resultant value.
    return (WORD)(((PartialSum >> 16) + PartialSum) & 0xffff);
}

static WORD detour_sum_data(DWORD dwSum, PBYTE pbData, DWORD cbData)
{
    while (cbData > 0) {
        dwSum += *((PWORD&)pbData)++;
        dwSum = (dwSum >> 16) + (dwSum & 0xffff);
        cbData -= sizeof(WORD);
    }
    return detour_sum_done(dwSum);
}

static WORD detour_sum_final(WORD wSum, PIMAGE_NT_HEADERS pinh)
{
    DETOUR_TRACE((".... : %08x (value: %08x)\n", wSum, pinh->OptionalHeader.CheckSum));

    // Subtract the two checksum words in the optional header from the computed.
    wSum = detour_sum_minus(wSum, ((PWORD)(&pinh->OptionalHeader.CheckSum))[0]);
    wSum = detour_sum_minus(wSum, ((PWORD)(&pinh->OptionalHeader.CheckSum))[1]);

    return wSum;
}

static WORD ChkSumRange(WORD wSum, HANDLE hProcess, PBYTE pbBeg, PBYTE pbEnd)
{
    BYTE rbPage[4096];

    while (pbBeg < pbEnd) {
        if (!ReadProcessMemory(hProcess, pbBeg, rbPage, sizeof(rbPage), NULL)) {
            DETOUR_TRACE(("ReadProcessMemory(idh) failed: %d\n", GetLastError()));
            break;
        }
        wSum = detour_sum_data(wSum, rbPage, sizeof(rbPage));
        pbBeg += sizeof(rbPage);
    }
    return wSum;
}

static WORD ComputeChkSum(HANDLE hProcess, PBYTE pbModule, PIMAGE_NT_HEADERS pinh)
{
    // See LdrVerifyMappedImageMatchesChecksum.

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));
    WORD wSum = 0;

    for (PBYTE pbLast = pbModule;;
         pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {

        if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) <= 0) {
            if (GetLastError() == ERROR_INVALID_PARAMETER) {
                break;
            }
            DETOUR_TRACE(("VirtualQueryEx(%08x) failed: %d\n",
                          pbLast, GetLastError()));
            break;
        }

        if (mbi.AllocationBase != pbModule) {
            break;
        }

        wSum = ChkSumRange(wSum,
                           hProcess,
                           (PBYTE)mbi.BaseAddress,
                           (PBYTE)mbi.BaseAddress + mbi.RegionSize);

        DETOUR_TRACE(("[%8p..%8p] : %04x\n",
                      (PBYTE)mbi.BaseAddress,
                      (PBYTE)mbi.BaseAddress + mbi.RegionSize,
                      wSum));
    }

    return detour_sum_final(wSum, pinh);
}

//////////////////////////////////////////////////////////////////////////////
//
// Find a region of memory in which we can create a replacement import table.
//
static PBYTE FindAndAllocateNearBase(HANDLE hProcess, PBYTE pbBase, DWORD cbAlloc)
{
    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));

    for (PBYTE pbLast = pbBase;;
         pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {

        if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) <= 0) {
            if (GetLastError() == ERROR_INVALID_PARAMETER) {
                break;
            }
            DETOUR_TRACE(("VirtualQueryEx(%08x) failed: %d\n",
                          pbLast, GetLastError()));
            break;
        }

        // Skip uncommitted regions and guard pages.
        //
        if ((mbi.State != MEM_FREE)) {
            continue;
        }

        PBYTE pbAddress = (PBYTE)(((DWORD_PTR)mbi.BaseAddress + 0xffff) & ~(DWORD_PTR)0xffff);

        DETOUR_TRACE(("Free region %p..%p\n",
                      mbi.BaseAddress,
                      (PBYTE)mbi.BaseAddress + mbi.RegionSize));

        for (; pbAddress < (PBYTE)mbi.BaseAddress + mbi.RegionSize; pbAddress += 0x10000) {
            PBYTE pbAlloc = (PBYTE)VirtualAllocEx(hProcess, pbAddress, cbAlloc,
                                                  MEM_RESERVE, PAGE_READWRITE);
            if (pbAlloc == NULL) {
                DETOUR_TRACE(("VirtualAllocEx(%p) failed: %d\n", pbAddress, GetLastError()));
                continue;
            }
            pbAlloc = (PBYTE)VirtualAllocEx(hProcess, pbAddress, cbAlloc,
                                            MEM_COMMIT, PAGE_READWRITE);
            if (pbAlloc == NULL) {
                DETOUR_TRACE(("VirtualAllocEx(%p) failed: %d\n", pbAddress, GetLastError()));
                continue;
            }
            DETOUR_TRACE(("[%p..%p] Allocated for import table.\n",
                          pbAlloc, pbAlloc + cbAlloc));
            return pbAlloc;
        }
    }
    return NULL;
}

static inline DWORD PadToDword(DWORD dw)
{
    return (dw + 3) & ~3u;
}

static inline DWORD PadToDwordPtr(DWORD dw)
{
    return (dw + 7) & ~7u;
}

static BOOL IsExe(HANDLE hProcess, PBYTE pbModule)
{
    IMAGE_DOS_HEADER idh;
    ZeroMemory(&idh, sizeof(idh));

    if (!ReadProcessMemory(hProcess, pbModule, &idh, sizeof(idh), NULL)) {
        DETOUR_TRACE(("ReadProcessMemory(idh) failed: %d\n", GetLastError()));
        return FALSE;
    }

    if (idh.e_magic != IMAGE_DOS_SIGNATURE) {
        // DETOUR_TRACE(("  No IMAGE_DOS_SIGNATURE\n"));
        return FALSE;
    }

    IMAGE_NT_HEADERS inh;
    ZeroMemory(&inh, sizeof(inh));

    if (!ReadProcessMemory(hProcess, pbModule + idh.e_lfanew, &inh, sizeof(inh), NULL)) {
        DETOUR_TRACE(("ReadProcessMemory(inh) failed: %d\n", GetLastError()));
        return FALSE;
    }

    if (inh.Signature != IMAGE_NT_SIGNATURE) {
        DETOUR_TRACE(("  No IMAGE_NT_SIGNATURE\n"));
        return FALSE;
    }

    if (inh.FileHeader.Characteristics & IMAGE_FILE_DLL) {
        DETOUR_TRACE(("  Characteristics: %08x\n", inh.FileHeader.Characteristics));
        return FALSE;
    }

    return TRUE;
}

PVOID FindExe(HANDLE hProcess)
{
    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));

    // Find the next memory region that contains a mapped PE image.
    //
    for (PBYTE pbLast = (PBYTE)0x10000;;
         pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {

        if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) <= 0) {
            if (GetLastError() == ERROR_INVALID_PARAMETER) {
                break;
            }
            DETOUR_TRACE(("VirtualQueryEx(%08x) failed: %d\n",
                          pbLast, GetLastError()));
            break;
        }

        // Skip uncommitted regions and guard pages.
        //
        if ((mbi.State != MEM_COMMIT) || (mbi.Protect & PAGE_GUARD)) {
            continue;
        }

        DETOUR_TRACE(("%8p..%8p [%8p]\n",
                      mbi.BaseAddress,
                      (PBYTE)mbi.BaseAddress + mbi.RegionSize,
                      mbi.AllocationBase));

        if (IsExe(hProcess, pbLast)) {
#if DETOUR_DEBUG
            for (PBYTE pbNext = (PBYTE)mbi.BaseAddress + mbi.RegionSize;;
                 pbNext = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {

                if (VirtualQueryEx(hProcess, (PVOID)pbNext, &mbi, sizeof(mbi)) <= 0) {
                    if (GetLastError() == ERROR_INVALID_PARAMETER) {
                        break;
                    }
                    DETOUR_TRACE(("VirtualQueryEx(%08x) failed: %d\n",
                                  pbNext, GetLastError()));
                    break;
                }

                // Skip uncommitted regions and guard pages.
                //
                if ((mbi.State != MEM_COMMIT) || (mbi.Protect & PAGE_GUARD)) {
                    continue;
                }
                DETOUR_TRACE(("%8p..%8p [%8p]\n",
                              mbi.BaseAddress,
                              (PBYTE)mbi.BaseAddress + mbi.RegionSize,
                              mbi.AllocationBase));

                IsExe(hProcess, pbNext);
            }
#endif
            return pbLast;
        }
    }
    return NULL;
}

static BOOL UpdateImports(HANDLE hProcess, LPCSTR *plpDlls, DWORD nDlls)
{
    BOOL fSucceeded = FALSE;
    BYTE * pbNew = NULL;
    DETOUR_EXE_RESTORE der;
    DWORD i;

    ZeroMemory(&der, sizeof(der));
    der.cb = sizeof(der);

    PBYTE pbModule = (PBYTE)FindExe(hProcess);

    IMAGE_DOS_HEADER idh;
    ZeroMemory(&idh, sizeof(idh));

    if (!ReadProcessMemory(hProcess, pbModule, &idh, sizeof(idh), NULL)) {
        DETOUR_TRACE(("ReadProcessMemory(idh) failed: %d\n", GetLastError()));

      finish:
        if (pbNew != NULL) {
            delete[] pbNew;
            pbNew = NULL;
        }
        return fSucceeded;
    }
    CopyMemory(&der.idh, &idh, sizeof(idh));
    der.pidh = (PIMAGE_DOS_HEADER)pbModule;

    if (idh.e_magic != IMAGE_DOS_SIGNATURE) {
        goto finish;
    }

    IMAGE_NT_HEADERS inh;
    ZeroMemory(&inh, sizeof(inh));

    if (!ReadProcessMemory(hProcess, pbModule + idh.e_lfanew, &inh, sizeof(inh), NULL)) {
        DETOUR_TRACE(("ReadProcessMemory(inh) failed: %d\n", GetLastError()));
        goto finish;
    }
    CopyMemory(&der.inh, &inh, sizeof(inh));
    der.pinh = (PIMAGE_NT_HEADERS)(pbModule + idh.e_lfanew);

    if (inh.Signature != IMAGE_NT_SIGNATURE) {
        goto finish;
    }

    if (inh.IMPORT_DIRECTORY.VirtualAddress == 0) {
        DETOUR_TRACE(("No IMAGE_DIRECTORY_ENTRY_IMPORT\n"));
        goto finish;
    }

    // Zero out the bound table so loader doesn't use it instead of our new table.
    inh.BOUND_DIRECTORY.VirtualAddress = 0;
    inh.BOUND_DIRECTORY.Size = 0;

    // Find the size of the mapped file.
    DWORD dwFileSize = 0;
    DWORD dwSec = idh.e_lfanew +
        FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +
        inh.FileHeader.SizeOfOptionalHeader;

    for (i = 0; i < inh.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER ish;
        ZeroMemory(&ish, sizeof(ish));

        if (!ReadProcessMemory(hProcess, pbModule + dwSec + sizeof(ish) * i, &ish,
                               sizeof(ish), NULL)) {
            DETOUR_TRACE(("ReadProcessMemory(inh) failed: %d\n", GetLastError()));
            goto finish;
        }

        DETOUR_TRACE(("ish[%d] : va=%p sr=%d\n", i, ish.VirtualAddress, ish.SizeOfRawData));

        // If the file didn't have an IAT_DIRECTORY, we create one...
        if (inh.IAT_DIRECTORY.VirtualAddress == 0 &&
            inh.IMPORT_DIRECTORY.VirtualAddress >= ish.VirtualAddress &&
            inh.IMPORT_DIRECTORY.VirtualAddress < ish.VirtualAddress + ish.SizeOfRawData) {

            inh.IAT_DIRECTORY.VirtualAddress = ish.VirtualAddress;
            inh.IAT_DIRECTORY.Size = ish.SizeOfRawData;
        }

        // Find the end of the file...
        if (dwFileSize < ish.PointerToRawData + ish.SizeOfRawData) {
            dwFileSize = ish.PointerToRawData + ish.SizeOfRawData;
        }
    }
    DETOUR_TRACE(("dwFileSize = %08x\n", dwFileSize));

    // Find the current checksum.
    WORD wBefore = ComputeChkSum(hProcess, pbModule, &inh);
    DETOUR_TRACE(("ChkSum: %04x + %08x => %08x\n", wBefore, dwFileSize, wBefore + dwFileSize));

    DETOUR_TRACE(("     Imports: %8p..%8p\n",
                  (DWORD_PTR)pbModule + inh.IMPORT_DIRECTORY.VirtualAddress,
                  (DWORD_PTR)pbModule + inh.IMPORT_DIRECTORY.VirtualAddress +
                  inh.IMPORT_DIRECTORY.Size));

    DWORD obRem = sizeof(IMAGE_IMPORT_DESCRIPTOR) * nDlls;
    DWORD obTab = PadToDwordPtr(obRem + inh.IMPORT_DIRECTORY.Size);
    DWORD obDll = obTab + sizeof(DWORD_PTR) * 4 * nDlls;
    DWORD obStr = obDll;
    DWORD cbNew = obStr;
    DWORD n;
    for (n = 0; n < nDlls; n++) {
        cbNew += PadToDword((DWORD)strlen(plpDlls[n]) + 1);
    }

    pbNew = new BYTE [cbNew];
    if (pbNew == NULL) {
        DETOUR_TRACE(("new BYTE [cbNew] failed.\n"));
        goto finish;
    }
    ZeroMemory(pbNew, cbNew);

    PBYTE pbBase = pbModule;
    PBYTE pbNext = pbBase
        + inh.OptionalHeader.BaseOfCode
        + inh.OptionalHeader.SizeOfCode
        + inh.OptionalHeader.SizeOfInitializedData
        + inh.OptionalHeader.SizeOfUninitializedData;
    if (pbBase < pbNext) {
        pbBase = pbNext;
    }
    DETOUR_TRACE(("pbBase = %p\n", pbBase));

    PBYTE pbNewIid = FindAndAllocateNearBase(hProcess, pbBase, cbNew);
    if (pbNewIid == NULL) {
        DETOUR_TRACE(("FindAndAllocateNearBase failed.\n"));
        goto finish;
    }

    DWORD dwProtect = 0;
    der.impDirProt = 0;
    if (!VirtualProtectEx(hProcess,
                          pbModule + inh.IMPORT_DIRECTORY.VirtualAddress,
                          inh.IMPORT_DIRECTORY.Size, PAGE_EXECUTE_READWRITE, &dwProtect)) {
        DETOUR_TRACE(("VirtualProtextEx(import) write failed: %d\n", GetLastError()));
        goto finish;
    }
    DETOUR_TRACE(("IMPORT_DIRECTORY perms=%x\n", dwProtect));
    der.impDirProt = dwProtect;

    DWORD obBase = (DWORD)(pbNewIid - pbModule);

    if (!ReadProcessMemory(hProcess,
                           pbModule + inh.IMPORT_DIRECTORY.VirtualAddress,
                           pbNew + obRem,
                           inh.IMPORT_DIRECTORY.Size, NULL)) {
        DETOUR_TRACE(("ReadProcessMemory(imports) failed: %d\n", GetLastError()));
        goto finish;
    }

    PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)pbNew;
    DWORD_PTR *pt;

    for (n = 0; n < nDlls; n++) {
        HRESULT hrRet = StringCchCopyA((char*)pbNew + obStr, cbNew - obStr, plpDlls[n]);
        if (FAILED(hrRet))
        {
            DETOUR_TRACE(("StringCchCopyA failed: %d\n", GetLastError()));
            goto finish;
        }

        DWORD nOffset = obTab + (sizeof(DWORD_PTR) * (4 * n));
        piid[n].OriginalFirstThunk = obBase + nOffset;
        pt = ((DWORD_PTR*)(pbNew + nOffset));
        pt[0] = IMAGE_ORDINAL_FLAG + 1;
        pt[1] = 0;

        nOffset = obTab + (sizeof(DWORD_PTR) * ((4 * n) + 2));
        piid[n].FirstThunk = obBase + nOffset;
        pt = ((DWORD_PTR*)(pbNew + nOffset));
        pt[0] = IMAGE_ORDINAL_FLAG + 1;
        pt[1] = 0;
        piid[n].TimeDateStamp = 0;
        piid[n].ForwarderChain = 0;
        piid[n].Name = obBase + obStr;

        obStr += PadToDword((DWORD)strlen(plpDlls[n]) + 1);
    }

    for (i = 0; i < nDlls + (inh.IMPORT_DIRECTORY.Size / sizeof(*piid)); i++) {
        DETOUR_TRACE(("%8d. Look=%08x Time=%08x Fore=%08x Name=%08x Addr=%08x\n",
                      i,
                      piid[i].OriginalFirstThunk,
                      piid[i].TimeDateStamp,
                      piid[i].ForwarderChain,
                      piid[i].Name,
                      piid[i].FirstThunk));
        if (piid[i].OriginalFirstThunk == 0 && piid[i].FirstThunk == 0) {
            break;
        }
    }

    if (!WriteProcessMemory(hProcess, pbNewIid, pbNew, obStr, NULL)) {
        DETOUR_TRACE(("WriteProcessMemory(iid) failed: %d\n", GetLastError()));
        goto finish;
    }

    DETOUR_TRACE(("obBase = %p..%p\n",
                  inh.IMPORT_DIRECTORY.VirtualAddress,
                  inh.IMPORT_DIRECTORY.VirtualAddress + inh.IMPORT_DIRECTORY.Size));
    DETOUR_TRACE(("obBase = %p..%p\n", obBase, obBase + obStr));

    inh.IMPORT_DIRECTORY.VirtualAddress = obBase;
    inh.IMPORT_DIRECTORY.Size = cbNew;

    /////////////////////////////////////////////////// Update the CLR header.
    //
    if (inh.CLR_DIRECTORY.VirtualAddress != 0 &&
        inh.CLR_DIRECTORY.Size != 0) {

        DETOUR_CLR_HEADER clr;
        PBYTE pbClr = pbModule + inh.CLR_DIRECTORY.VirtualAddress;

        if (!ReadProcessMemory(hProcess, pbClr, &clr, sizeof(clr), NULL)) {
            DETOUR_TRACE(("ReadProcessMemory(clr) failed: %d\n", GetLastError()));
            goto finish;
        }

        der.pclrFlags = (PULONG)(pbClr + offsetof(DETOUR_CLR_HEADER, Flags));
        der.clrFlags = clr.Flags;

        clr.Flags &= 0xfffffffe;    // Clear the IL_ONLY flag.

        if (!VirtualProtectEx(hProcess, pbClr, sizeof(clr), PAGE_READWRITE, &dwProtect)) {
            DETOUR_TRACE(("VirtualProtextEx(clr) write failed: %d\n", GetLastError()));
            goto finish;
        }

        if (!WriteProcessMemory(hProcess, pbClr, &clr, sizeof(clr), NULL)) {
            DETOUR_TRACE(("WriteProcessMemory(clr) failed: %d\n", GetLastError()));
            goto finish;
        }

        if (!VirtualProtectEx(hProcess, pbClr, sizeof(clr), dwProtect, &dwProtect)) {
            DETOUR_TRACE(("VirtualProtextEx(clr) restore failed: %d\n", GetLastError()));
            goto finish;
        }
    }

    /////////////////////// Update the NT header for the import new directory.
    /////////////////////////////// Update the DOS header to fix the checksum.
    //
    if (!VirtualProtectEx(hProcess, pbModule, inh.OptionalHeader.SizeOfHeaders,
                          PAGE_EXECUTE_READWRITE, &dwProtect)) {
        DETOUR_TRACE(("VirtualProtextEx(inh) write failed: %d\n", GetLastError()));
        goto finish;
    }

    idh.e_res[0] = 0;
    if (!WriteProcessMemory(hProcess, pbModule, &idh, sizeof(idh), NULL)) {
        DETOUR_TRACE(("WriteProcessMemory(idh) failed: %d\n", GetLastError()));
        goto finish;
    }

    if (!WriteProcessMemory(hProcess, pbModule + idh.e_lfanew, &inh, sizeof(inh), NULL)) {
        DETOUR_TRACE(("WriteProcessMemory(inh) failed: %d\n", GetLastError()));
        goto finish;
    }

    WORD wDuring = ComputeChkSum(hProcess, pbModule, &inh);
    DETOUR_TRACE(("ChkSum: %04x + %08x => %08x\n", wDuring, dwFileSize, wDuring + dwFileSize));

    idh.e_res[0] = detour_sum_minus(idh.e_res[0], detour_sum_minus(wDuring, wBefore));

    if (!WriteProcessMemory(hProcess, pbModule, &idh, sizeof(idh), NULL)) {
        DETOUR_TRACE(("WriteProcessMemory(idh) failed: %d\n", GetLastError()));
        goto finish;
    }

    if (!VirtualProtectEx(hProcess, pbModule, inh.OptionalHeader.SizeOfHeaders,
                          dwProtect, &dwProtect)) {
        DETOUR_TRACE(("VirtualProtextEx(idh) restore failed: %d\n", GetLastError()));
        goto finish;
    }

    WORD wAfter = ComputeChkSum(hProcess, pbModule, &inh);
    DETOUR_TRACE(("ChkSum: %04x + %08x => %08x\n", wAfter, dwFileSize, wAfter + dwFileSize));
    DETOUR_TRACE(("Before: %08x, After: %08x\n", wBefore + dwFileSize, wAfter + dwFileSize));

    if (wBefore != wAfter) {
        DETOUR_TRACE(("Restore of checksum failed %04x != %04x.\n", wBefore, wAfter));
        goto finish;
    }

    if (!DetourCopyPayloadToProcess(hProcess, DETOUR_EXE_RESTORE_GUID, &der, sizeof(der))) {
        DETOUR_TRACE(("DetourCopyPayloadToProcess failed: %d\n", GetLastError()));
        goto finish;
    }

    fSucceeded = TRUE;
    goto finish;
}

//////////////////////////////////////////////////////////////////////////////
//
BOOL WINAPI DetourCreateProcessWithDllA(LPCSTR lpApplicationName,
                                        __in_z LPSTR lpCommandLine,
                                        LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                        LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                        BOOL bInheritHandles,
                                        DWORD dwCreationFlags,
                                        LPVOID lpEnvironment,
                                        LPCSTR lpCurrentDirectory,
                                        LPSTARTUPINFOA lpStartupInfo,
                                        LPPROCESS_INFORMATION lpProcessInformation,
                                        LPCSTR lpDetouredDllFullName,
                                        LPCSTR lpDllName,
                                        PDETOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA)
{
    DWORD dwMyCreationFlags = (dwCreationFlags | CREATE_SUSPENDED);
    PROCESS_INFORMATION pi;

    if (pfCreateProcessA == NULL) {
        pfCreateProcessA = CreateProcessA;
    }

    if (!pfCreateProcessA(lpApplicationName,
                          lpCommandLine,
                          lpProcessAttributes,
                          lpThreadAttributes,
                          bInheritHandles,
                          dwMyCreationFlags,
                          lpEnvironment,
                          lpCurrentDirectory,
                          lpStartupInfo,
                          &pi)) {
        return FALSE;
    }

    LPCSTR rlpDlls[2];
    DWORD nDlls = 0;
    if (lpDetouredDllFullName != NULL) {
        rlpDlls[nDlls++] = lpDetouredDllFullName;
    }
    if (lpDllName != NULL) {
        rlpDlls[nDlls++] = lpDllName;
    }

    if (!UpdateImports(pi.hProcess, rlpDlls, nDlls)) {
        return FALSE;
    }

    if (lpProcessInformation) {
        CopyMemory(lpProcessInformation, &pi, sizeof(pi));
    }

    if (!(dwCreationFlags & CREATE_SUSPENDED)) {
        ResumeThread(pi.hThread);
    }
    return TRUE;
}


BOOL WINAPI DetourCreateProcessWithDllW(LPCWSTR lpApplicationName,
                                        __in_z LPWSTR lpCommandLine,
                                        LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                        LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                        BOOL bInheritHandles,
                                        DWORD dwCreationFlags,
                                        LPVOID lpEnvironment,
                                        LPCWSTR lpCurrentDirectory,
                                        LPSTARTUPINFOW lpStartupInfo,
                                        LPPROCESS_INFORMATION lpProcessInformation,
                                        LPCSTR lpDetouredDllFullName,
                                        LPCSTR lpDllName,
                                        PDETOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW)
{
    DWORD dwMyCreationFlags = (dwCreationFlags | CREATE_SUSPENDED);
    PROCESS_INFORMATION pi;

    if (pfCreateProcessW == NULL) {
        pfCreateProcessW = CreateProcessW;
    }

    if (!pfCreateProcessW(lpApplicationName,
                          lpCommandLine,
                          lpProcessAttributes,
                          lpThreadAttributes,
                          bInheritHandles,
                          dwMyCreationFlags,
                          lpEnvironment,
                          lpCurrentDirectory,
                          lpStartupInfo,
                          &pi)) {
        return FALSE;
    }

    LPCSTR rlpDlls[2];
    DWORD nDlls = 0;
    if (lpDetouredDllFullName != NULL) {
        rlpDlls[nDlls++] = lpDetouredDllFullName;
    }
    if (lpDllName != NULL) {
        rlpDlls[nDlls++] = lpDllName;
    }

    if (!UpdateImports(pi.hProcess, rlpDlls, nDlls)) {
        return FALSE;
    }

    if (lpProcessInformation) {
        CopyMemory(lpProcessInformation, &pi, sizeof(pi));
    }

    if (!(dwCreationFlags & CREATE_SUSPENDED)) {
        ResumeThread(pi.hThread);
    }
    return TRUE;
}

BOOL WINAPI DetourCopyPayloadToProcess(HANDLE hProcess,
                                       REFGUID rguid,
                                       PVOID pData,
                                       DWORD cbData)
{
    DWORD cbTotal = (sizeof(IMAGE_DOS_HEADER) +
                     sizeof(IMAGE_NT_HEADERS) +
                     sizeof(IMAGE_SECTION_HEADER) +
                     sizeof(DETOUR_SECTION_HEADER) +
                     sizeof(DETOUR_SECTION_RECORD) +
                     cbData);

    PBYTE pbBase = (PBYTE)VirtualAllocEx(hProcess, NULL, cbTotal,
                                         MEM_COMMIT, PAGE_READWRITE);
    if (pbBase == NULL) {
        DETOUR_TRACE(("VirtualAllocEx(%d) failed: %d\n", cbTotal, GetLastError()));
        return FALSE;
    }

    PBYTE pbTarget = pbBase;
    IMAGE_DOS_HEADER idh;
    IMAGE_NT_HEADERS inh;
    IMAGE_SECTION_HEADER ish;
    DETOUR_SECTION_HEADER dsh;
    DETOUR_SECTION_RECORD dsr;
    SIZE_T cbWrote = 0;

    ZeroMemory(&idh, sizeof(idh));
    idh.e_magic = IMAGE_DOS_SIGNATURE;
    idh.e_lfanew = sizeof(idh);
    if (!WriteProcessMemory(hProcess, pbTarget, &idh, sizeof(idh), &cbWrote) ||
        cbWrote != sizeof(idh)) {
        DETOUR_TRACE(("WriteProcessMemory(idh) failed: %d\n", GetLastError()));
        return FALSE;
    }
    pbTarget += sizeof(idh);

    ZeroMemory(&inh, sizeof(inh));
    inh.Signature = IMAGE_NT_SIGNATURE;
    inh.FileHeader.SizeOfOptionalHeader = sizeof(inh.OptionalHeader);
    inh.FileHeader.Characteristics = IMAGE_FILE_DLL;
    inh.FileHeader.NumberOfSections = 1;
    if (!WriteProcessMemory(hProcess, pbTarget, &inh, sizeof(inh), &cbWrote) ||
        cbWrote != sizeof(inh)) {
        return FALSE;
    }
    pbTarget += sizeof(inh);

    ZeroMemory(&ish, sizeof(ish));
    memcpy(ish.Name, ".detour", sizeof(ish.Name));
    ish.VirtualAddress = (DWORD)((pbTarget + sizeof(ish)) - pbBase);
    ish.SizeOfRawData = (sizeof(DETOUR_SECTION_HEADER) +
                         sizeof(DETOUR_SECTION_RECORD) +
                         cbData);
    if (!WriteProcessMemory(hProcess, pbTarget, &ish, sizeof(ish), &cbWrote) ||
        cbWrote != sizeof(ish)) {
        return FALSE;
    }
    pbTarget += sizeof(ish);

    ZeroMemory(&dsh, sizeof(dsh));
    dsh.cbHeaderSize = sizeof(dsh);
    dsh.nSignature = DETOUR_SECTION_HEADER_SIGNATURE;
    dsh.nDataOffset = sizeof(DETOUR_SECTION_HEADER);
    dsh.cbDataSize = (sizeof(DETOUR_SECTION_HEADER) +
                      sizeof(DETOUR_SECTION_RECORD) +
                      cbData);
    if (!WriteProcessMemory(hProcess, pbTarget, &dsh, sizeof(dsh), &cbWrote) ||
        cbWrote != sizeof(dsh)) {
        return FALSE;
    }
    pbTarget += sizeof(dsh);

    ZeroMemory(&dsr, sizeof(dsr));
    dsr.cbBytes = cbData + sizeof(DETOUR_SECTION_RECORD);
    dsr.nReserved = 0;
    dsr.guid = rguid;
    if (!WriteProcessMemory(hProcess, pbTarget, &dsr, sizeof(dsr), &cbWrote) ||
        cbWrote != sizeof(dsr)) {
        return FALSE;
    }
    pbTarget += sizeof(dsr);

    if (!WriteProcessMemory(hProcess, pbTarget, pData, cbData, &cbWrote) ||
        cbWrote != cbData) {
        return FALSE;
    }
    pbTarget += cbData;

    DETOUR_TRACE(("Copied %d bytes into target process at %p\n",
                  cbTotal, pbTarget - cbTotal));
    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.
