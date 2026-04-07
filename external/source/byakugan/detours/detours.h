//////////////////////////////////////////////////////////////////////////////
//
//  Core Detours Functionality (detours.h of detours.lib)
//
//  Microsoft Research Detours Package, Version 2.1.
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

#pragma once
#ifndef _DETOURS_H_
#define _DETOURS_H_

#define DETOURS_VERSION     20100   // 2.1.0

//////////////////////////////////////////////////////////////////////////////
//

#if (_MSC_VER < 1299)
typedef LONG LONG_PTR;
typedef ULONG ULONG_PTR;
#endif

#ifndef __in_z
#define __in_z
#endif

//////////////////////////////////////////////////////////////////////////////
//
#ifndef GUID_DEFINED
#define GUID_DEFINED
typedef struct  _GUID
{
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[ 8 ];
} GUID;

#ifdef INITGUID
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
        const GUID name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }
#else
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    const GUID name
#endif // INITGUID
#endif // !GUID_DEFINED

#if defined(__cplusplus)
#ifndef _REFGUID_DEFINED
#define _REFGUID_DEFINED
#define REFGUID             const GUID &
#endif // !_REFGUID_DEFINED
#else // !__cplusplus
#ifndef _REFGUID_DEFINED
#define _REFGUID_DEFINED
#define REFGUID             const GUID * const
#endif // !_REFGUID_DEFINED
#endif // !__cplusplus

//
//////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/////////////////////////////////////////////////// Instruction Target Macros.
//
#define DETOUR_INSTRUCTION_TARGET_NONE          ((PVOID)0)
#define DETOUR_INSTRUCTION_TARGET_DYNAMIC       ((PVOID)(LONG_PTR)-1)
#define DETOUR_SECTION_HEADER_SIGNATURE         0x00727444   // "Dtr\0"

extern const GUID DETOUR_EXE_RESTORE_GUID;

#define DETOUR_TRAMPOLINE_SIGNATURE             0x21727444  // Dtr!
typedef struct _DETOUR_TRAMPOLINE DETOUR_TRAMPOLINE, *PDETOUR_TRAMPOLINE;

/////////////////////////////////////////////////////////// Binary Structures.
//
#pragma pack(push, 8)
typedef struct _DETOUR_SECTION_HEADER
{
    DWORD       cbHeaderSize;
    DWORD       nSignature;
    DWORD       nDataOffset;
    DWORD       cbDataSize;

    DWORD       nOriginalImportVirtualAddress;
    DWORD       nOriginalImportSize;
    DWORD       nOriginalBoundImportVirtualAddress;
    DWORD       nOriginalBoundImportSize;

    DWORD       nOriginalIatVirtualAddress;
    DWORD       nOriginalIatSize;
    DWORD       nOriginalSizeOfImage;
    DWORD       cbPrePE;

    DWORD       nOriginalClrFlags;
    DWORD       reserved1;
    DWORD       reserved2;
    DWORD       reserved3;

    // Followed by cbPrePE bytes of data.
} DETOUR_SECTION_HEADER, *PDETOUR_SECTION_HEADER;

typedef struct _DETOUR_SECTION_RECORD
{
    DWORD       cbBytes;
    DWORD       nReserved;
    GUID        guid;
} DETOUR_SECTION_RECORD, *PDETOUR_SECTION_RECORD;

typedef struct _DETOUR_CLR_HEADER
{
    // Header versioning
    ULONG                   cb;
    USHORT                  MajorRuntimeVersion;
    USHORT                  MinorRuntimeVersion;

    // Symbol table and startup information
    IMAGE_DATA_DIRECTORY    MetaData;
    ULONG                   Flags;

    // Followed by the rest of the header.
} DETOUR_CLR_HEADER, *PDETOUR_CLR_HEADER;

typedef struct _DETOUR_EXE_RESTORE
{
    ULONG               cb;

    PIMAGE_DOS_HEADER   pidh;
    PIMAGE_NT_HEADERS   pinh;
    PULONG              pclrFlags;
    DWORD               impDirProt;

    IMAGE_DOS_HEADER    idh;
    IMAGE_NT_HEADERS    inh;
    ULONG               clrFlags;
} DETOUR_EXE_RESTORE, *PDETOUR_EXE_RESTORE;

#pragma pack(pop)

#define DETOUR_SECTION_HEADER_DECLARE(cbSectionSize) \
{ \
      sizeof(DETOUR_SECTION_HEADER),\
      DETOUR_SECTION_HEADER_SIGNATURE,\
      sizeof(DETOUR_SECTION_HEADER),\
      (cbSectionSize),\
      \
      0,\
      0,\
      0,\
      0,\
      \
      0,\
      0,\
      0,\
      0,\
}

///////////////////////////////////////////////////////////// Binary Typedefs.
//
typedef BOOL (CALLBACK *PF_DETOUR_BINARY_BYWAY_CALLBACK)(PVOID pContext,
                                                         PCHAR pszFile,
                                                         PCHAR *ppszOutFile);

typedef BOOL (CALLBACK *PF_DETOUR_BINARY_FILE_CALLBACK)(PVOID pContext,
                                                        PCHAR pszOrigFile,
                                                        PCHAR pszFile,
                                                        PCHAR *ppszOutFile);

typedef BOOL (CALLBACK *PF_DETOUR_BINARY_SYMBOL_CALLBACK)(PVOID pContext,
                                                          ULONG nOrigOrdinal,
                                                          ULONG nOrdinal,
                                                          ULONG *pnOutOrdinal,
                                                          PCHAR pszOrigSymbol,
                                                          PCHAR pszSymbol,
                                                          PCHAR *ppszOutSymbol);

typedef BOOL (CALLBACK *PF_DETOUR_BINARY_COMMIT_CALLBACK)(PVOID pContext);

typedef BOOL (CALLBACK *PF_DETOUR_ENUMERATE_EXPORT_CALLBACK)(PVOID pContext,
                                                             ULONG nOrdinal,
                                                             PCHAR pszName,
                                                             PVOID pCode);

typedef VOID * PDETOUR_BINARY;
typedef VOID * PDETOUR_LOADED_BINARY;

//////////////////////////////////////////////////////////// Detours 2.1 APIs.
//

LONG WINAPI DetourTransactionBegin();
LONG WINAPI DetourTransactionAbort();
LONG WINAPI DetourTransactionCommit();
LONG WINAPI DetourTransactionCommitEx(PVOID **pppFailedPointer);

LONG WINAPI DetourUpdateThread(HANDLE hThread);

LONG WINAPI DetourAttach(PVOID *ppPointer,
                         PVOID pDetour);

LONG WINAPI DetourAttachEx(PVOID *ppPointer,
                           PVOID pDetour,
                           PDETOUR_TRAMPOLINE *ppRealTrampoline,
                           PVOID *ppRealTarget,
                           PVOID *ppRealDetour);

LONG WINAPI DetourDetach(PVOID *ppPointer,
                         PVOID pDetour);

VOID WINAPI DetourSetIgnoreTooSmall(BOOL fIgnore);

////////////////////////////////////////////////////////////// Code Functions.
//
PVOID WINAPI DetourFindFunction(PCSTR pszModule, PCSTR pszFunction);
PVOID WINAPI DetourCodeFromPointer(PVOID pPointer, PVOID *ppGlobals);

PVOID WINAPI DetourCopyInstruction(PVOID pDst, PVOID pSrc, PVOID *ppTarget);
PVOID WINAPI DetourCopyInstructionEx(PVOID pDst,
                                     PVOID pSrc,
                                     PVOID *ppTarget,
                                     LONG *plExtra);

///////////////////////////////////////////////////// Loaded Binary Functions.
//
HMODULE WINAPI DetourEnumerateModules(HMODULE hModuleLast);
PVOID WINAPI DetourGetEntryPoint(HMODULE hModule);
ULONG WINAPI DetourGetModuleSize(HMODULE hModule);
BOOL WINAPI DetourEnumerateExports(HMODULE hModule,
                                   PVOID pContext,
                                   PF_DETOUR_ENUMERATE_EXPORT_CALLBACK pfExport);

PVOID WINAPI DetourFindPayload(HMODULE hModule, REFGUID rguid, DWORD *pcbData);
DWORD WINAPI DetourGetSizeOfPayloads(HMODULE hModule);

///////////////////////////////////////////////// Persistent Binary Functions.
//

PDETOUR_BINARY WINAPI DetourBinaryOpen(HANDLE hFile);
PVOID WINAPI DetourBinaryEnumeratePayloads(PDETOUR_BINARY pBinary,
                                           GUID *pGuid,
                                           DWORD *pcbData,
                                           DWORD *pnIterator);
PVOID WINAPI DetourBinaryFindPayload(PDETOUR_BINARY pBinary,
                                     REFGUID rguid,
                                     DWORD *pcbData);
PVOID WINAPI DetourBinarySetPayload(PDETOUR_BINARY pBinary,
                                    REFGUID rguid,
                                    PVOID pData,
                                    DWORD cbData);
BOOL WINAPI DetourBinaryDeletePayload(PDETOUR_BINARY pBinary, REFGUID rguid);
BOOL WINAPI DetourBinaryPurgePayloads(PDETOUR_BINARY pBinary);
BOOL WINAPI DetourBinaryResetImports(PDETOUR_BINARY pBinary);
BOOL WINAPI DetourBinaryEditImports(PDETOUR_BINARY pBinary,
                                    PVOID pContext,
                                    PF_DETOUR_BINARY_BYWAY_CALLBACK pfByway,
                                    PF_DETOUR_BINARY_FILE_CALLBACK pfFile,
                                    PF_DETOUR_BINARY_SYMBOL_CALLBACK pfSymbol,
                                    PF_DETOUR_BINARY_COMMIT_CALLBACK pfCommit);
BOOL WINAPI DetourBinaryWrite(PDETOUR_BINARY pBinary, HANDLE hFile);
BOOL WINAPI DetourBinaryClose(PDETOUR_BINARY pBinary);

/////////////////////////////////////////////////// Create Process & Load Dll.
//
typedef BOOL (WINAPI *PDETOUR_CREATE_PROCESS_ROUTINEA)
    (LPCSTR lpApplicationName,
     LPSTR lpCommandLine,
     LPSECURITY_ATTRIBUTES lpProcessAttributes,
     LPSECURITY_ATTRIBUTES lpThreadAttributes,
     BOOL bInheritHandles,
     DWORD dwCreationFlags,
     LPVOID lpEnvironment,
     LPCSTR lpCurrentDirectory,
     LPSTARTUPINFOA lpStartupInfo,
     LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (WINAPI *PDETOUR_CREATE_PROCESS_ROUTINEW)
    (LPCWSTR lpApplicationName,
     LPWSTR lpCommandLine,
     LPSECURITY_ATTRIBUTES lpProcessAttributes,
     LPSECURITY_ATTRIBUTES lpThreadAttributes,
     BOOL bInheritHandles,
     DWORD dwCreationFlags,
     LPVOID lpEnvironment,
     LPCWSTR lpCurrentDirectory,
     LPSTARTUPINFOW lpStartupInfo,
     LPPROCESS_INFORMATION lpProcessInformation);

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
                                        PDETOUR_CREATE_PROCESS_ROUTINEA
                                        pfCreateProcessA);

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
                                        PDETOUR_CREATE_PROCESS_ROUTINEW
                                        pfCreateProcessW);

#ifdef UNICODE
#define DetourCreateProcessWithDll  DetourCreateProcessWithDllW
#define PDETOUR_CREATE_PROCESS_ROUTINE     PDETOUR_CREATE_PROCESS_ROUTINEW
#else
#define DetourCreateProcessWithDll  DetourCreateProcessWithDllA
#define PDETOUR_CREATE_PROCESS_ROUTINE     PDETOUR_CREATE_PROCESS_ROUTINEA
#endif // !UNICODE

BOOL WINAPI DetourCopyPayloadToProcess(HANDLE hProcess,
                                       REFGUID rguid,
                                       PVOID pvData,
                                       DWORD cbData);
BOOL WINAPI DetourRestoreAfterWith();
BOOL WINAPI DetourRestoreAfterWithEx(PVOID pvData, DWORD cbData);

HMODULE WINAPI DetourGetDetouredMarker();

//
//////////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
}
#endif // __cplusplus

//////////////////////////////////////////////// Detours Internal Definitions.
//
#ifdef __cplusplus
#ifdef DETOURS_INTERNAL

#ifndef __deref_out
#define __deref_out
#endif

#ifndef __deref
#define __deref
#endif

//////////////////////////////////////////////////////////////////////////////
//
#if (_MSC_VER < 1299)
#include <imagehlp.h>
typedef IMAGEHLP_MODULE IMAGEHLP_MODULE64;
typedef PIMAGEHLP_MODULE PIMAGEHLP_MODULE64;
typedef IMAGEHLP_SYMBOL SYMBOL_INFO;
typedef PIMAGEHLP_SYMBOL PSYMBOL_INFO;

static inline
LONG InterlockedCompareExchange(LONG *ptr, LONG nval, LONG oval)
{
    return (LONG)::InterlockedCompareExchange((PVOID*)ptr, (PVOID)nval, (PVOID)oval);
}
#else
#include <dbghelp.h>
#endif

#ifdef IMAGEAPI // defined by DBGHELP.H
typedef LPAPI_VERSION (NTAPI *PF_ImagehlpApiVersionEx)(LPAPI_VERSION AppVersion);

typedef BOOL (NTAPI *PF_SymInitialize)(IN HANDLE hProcess,
                                       IN LPCSTR UserSearchPath,
                                       IN BOOL fInvadeProcess);
typedef DWORD (NTAPI *PF_SymSetOptions)(IN DWORD SymOptions);
typedef DWORD (NTAPI *PF_SymGetOptions)(VOID);
typedef DWORD64 (NTAPI *PF_SymLoadModule64)(IN HANDLE hProcess,
                                            IN HANDLE hFile,
                                            IN PSTR ImageName,
                                            IN PSTR ModuleName,
                                            IN DWORD64 BaseOfDll,
                                            IN DWORD SizeOfDll);
typedef BOOL (NTAPI *PF_SymGetModuleInfo64)(IN HANDLE hProcess,
                                            IN DWORD64 qwAddr,
                                            OUT PIMAGEHLP_MODULE64 ModuleInfo);
typedef BOOL (NTAPI *PF_SymFromName)(IN HANDLE hProcess,
                                     IN LPSTR Name,
                                     OUT PSYMBOL_INFO Symbol);

typedef struct _DETOUR_SYM_INFO
{
    HANDLE                  hProcess;
    HMODULE                 hDbgHelp;
    PF_ImagehlpApiVersionEx pfImagehlpApiVersionEx;
    PF_SymInitialize        pfSymInitialize;
    PF_SymSetOptions        pfSymSetOptions;
    PF_SymGetOptions        pfSymGetOptions;
    PF_SymLoadModule64      pfSymLoadModule64;
    PF_SymGetModuleInfo64   pfSymGetModuleInfo64;
    PF_SymFromName          pfSymFromName;
} DETOUR_SYM_INFO, *PDETOUR_SYM_INFO;

PDETOUR_SYM_INFO DetourLoadDbgHelp(VOID);

#endif // IMAGEAPI

#ifndef DETOUR_TRACE
#if DETOUR_DEBUG
#define DETOUR_TRACE(x) printf x
#define DETOUR_BREAK()  DebugBreak()
#include <stdio.h>
#include <limits.h>
#else
#define DETOUR_TRACE(x)
#define DETOUR_BREAK()
#endif
#endif

#ifdef DETOURS_IA64
__declspec(align(16)) struct DETOUR_IA64_BUNDLE
{
  public:
    union
    {
        BYTE    data[16];
        UINT64  wide[2];
    };

  public:
    struct DETOUR_IA64_METADATA;

    typedef BOOL (DETOUR_IA64_BUNDLE::* DETOUR_IA64_METACOPY)
        (const DETOUR_IA64_METADATA *pMeta, DETOUR_IA64_BUNDLE *pDst) const;

    enum {
        A_UNIT  = 1u,
        I_UNIT  = 2u,
        M_UNIT  = 3u,
        B_UNIT  = 4u,
        F_UNIT  = 5u,
        L_UNIT  = 6u,
        X_UNIT  = 7u,
        UNIT_MASK = 7u,
        STOP    = 8u
    };
    struct DETOUR_IA64_METADATA
    {
        ULONG       nTemplate       : 8;    // Instruction template.
        ULONG       nUnit0          : 4;    // Unit for slot 0
        ULONG       nUnit1          : 4;    // Unit for slot 1
        ULONG       nUnit2          : 4;    // Unit for slot 2
        DETOUR_IA64_METACOPY    pfCopy;     // Function pointer.
    };

  protected:
    BOOL CopyBytes(const DETOUR_IA64_METADATA *pMeta, DETOUR_IA64_BUNDLE *pDst) const;
    BOOL CopyBytesMMB(const DETOUR_IA64_METADATA *pMeta, DETOUR_IA64_BUNDLE *pDst) const;
    BOOL CopyBytesMBB(const DETOUR_IA64_METADATA *pMeta, DETOUR_IA64_BUNDLE *pDst) const;
    BOOL CopyBytesBBB(const DETOUR_IA64_METADATA *pMeta, DETOUR_IA64_BUNDLE *pDst) const;
    BOOL CopyBytesMLX(const DETOUR_IA64_METADATA *pMeta, DETOUR_IA64_BUNDLE *pDst) const;

    static const DETOUR_IA64_METADATA s_rceCopyTable[33];

  public:
    // 120 112 104 96 88 80 72 64 56 48 40 32 24 16  8  0
    //  f.  e.  d. c. b. a. 9. 8. 7. 6. 5. 4. 3. 2. 1. 0.

    //                                      00
    // f.e. d.c. b.a. 9.8. 7.6. 5.4. 3.2. 1.0.
    // 0000 0000 0000 0000 0000 0000 0000 001f : Template [4..0]
    // 0000 0000 0000 0000 0000 03ff ffff ffe0 : Zero [ 41..  5]
    // 0000 0000 0000 0000 0000 3c00 0000 0000 : Zero [ 45.. 42]
    // 0000 0000 0007 ffff ffff c000 0000 0000 : One  [ 82.. 46]
    // 0000 0000 0078 0000 0000 0000 0000 0000 : One  [ 86.. 83]
    // 0fff ffff ff80 0000 0000 0000 0000 0000 : Two  [123.. 87]
    // f000 0000 0000 0000 0000 0000 0000 0000 : Two  [127..124]
    BYTE    GetTemplate() const;
    BYTE    GetInst0() const;
    BYTE    GetInst1() const;
    BYTE    GetInst2() const;
    BYTE    GetUnit0() const;
    BYTE    GetUnit1() const;
    BYTE    GetUnit2() const;
    UINT64  GetData0() const;
    UINT64  GetData1() const;
    UINT64  GetData2() const;

  public:
    BOOL    IsBrl() const;
    VOID    SetBrl();
    VOID    SetBrl(UINT64 target);
    UINT64  GetBrlTarget() const;
    VOID    SetBrlTarget(UINT64 target);
    VOID    SetBrlImm(UINT64 imm);
    UINT64  GetBrlImm() const;

    BOOL    IsMovlGp() const;
    UINT64  GetMovlGp() const;
    VOID    SetMovlGp(UINT64 gp);

    VOID    SetInst0(BYTE nInst);
    VOID    SetInst1(BYTE nInst);
    VOID    SetInst2(BYTE nInst);
    VOID    SetData0(UINT64 nData);
    VOID    SetData1(UINT64 nData);
    VOID    SetData2(UINT64 nData);
    BOOL    SetNop0();
    BOOL    SetNop1();
    BOOL    SetNop2();
    BOOL    SetStop();

    BOOL    Copy(DETOUR_IA64_BUNDLE *pDst) const;
};
#endif // DETOURS_IA64

//////////////////////////////////////////////////////////////////////////////

#endif // DETOURS_INTERNAL
#endif // __cplusplus

#endif // _DETOURS_H_
//
////////////////////////////////////////////////////////////////  End of File.
