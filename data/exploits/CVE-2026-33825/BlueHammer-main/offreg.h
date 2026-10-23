/*++

Copyright (c) Microsoft Corporation

Module Name:

    offreg.h

Abstract:

    This module contains the header file for the
    offreg utility.

--*/

#pragma once

#ifndef __OFFREG_H__
#define __OFFREG_H__

#ifdef __cplusplus
extern "C"
{
#endif


#if defined(OFFREG_DLL)
#define ORAPI _declspec(dllexport) __stdcall
#else
#define ORAPI _declspec(dllimport) __stdcall
#endif

    typedef PVOID   ORHKEY;
    typedef ORHKEY* PORHKEY;

    VOID
        ORAPI
        ORGetVersion(
            _Out_ PDWORD pdwMajorVersion,
            _Out_ PDWORD pdwMinorVersion
        );

    DWORD
        ORAPI
        OROpenHive(
            _In_ PCWSTR FilePath,
            _Out_ PORHKEY HORKey
        );

    DWORD
        ORAPI
        OROpenHiveByHandle(
            _In_ HANDLE FileHandle,
            _Out_ PORHKEY HORKey
        );

    DWORD
        ORAPI
        ORCreateHive(
            _Out_ PORHKEY HORKey
        );

    DWORD
        ORAPI
        ORCloseHive(
            _In_ ORHKEY Handle
        );

    DWORD
        ORAPI
        ORSaveHive(
            _In_ ORHKEY HORKey,
            _In_ PCWSTR HivePath,
            _In_ DWORD OsMajorVersion,
            _In_ DWORD OsMinorVersion
        );

    DWORD
        ORAPI
        OROpenKey(
            _In_ ORHKEY Handle,
            _In_opt_ PCWSTR lpSubKey,
            _Out_ PORHKEY phkResult
        );

    DWORD
        ORAPI
        ORCloseKey(
            _In_ ORHKEY KeyHandle
        );

    DWORD
        ORAPI
        ORCreateKey(
            _In_ ORHKEY KeyHandle,
            _In_ PCWSTR lpSubKey,
            _In_opt_ PWSTR lpClass,
            _In_opt_ DWORD dwOptions,
            _In_opt_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
            _Out_ PORHKEY  phkResult,
            _Out_opt_ PDWORD pdwDisposition
        );

    DWORD
        ORAPI
        ORDeleteKey(
            _In_ ORHKEY Handle,
            _In_opt_ PCWSTR lpSubKey
        );

    DWORD
        ORAPI
        ORQueryInfoKey(
            _In_ ORHKEY Handle,
            _Out_writes_opt_(*lpcClass) PWSTR lpClass,
            _Inout_opt_ PDWORD lpcClass,
            _Out_opt_ PDWORD lpcSubKeys,
            _Out_opt_ PDWORD lpcMaxSubKeyLen,
            _Out_opt_ PDWORD lpcMaxClassLen,
            _Out_opt_ PDWORD lpcValues,
            _Out_opt_ PDWORD lpcMaxValueNameLen,
            _Out_opt_ PDWORD lpcMaxValueLen,
            _Out_opt_ PDWORD lpcbSecurityDescriptor,
            _Out_opt_ PFILETIME lpftLastWriteTime
        );

    DWORD
        ORAPI
        OREnumKey(
            _In_ ORHKEY Handle,
            _In_ DWORD dwIndex,
            _Out_writes_(*lpcName) PWSTR lpName,
            _Inout_ PDWORD lpcName,
            _Out_writes_opt_(*lpcClass) PWSTR lpClass,
            _Inout_opt_ PDWORD lpcClass,
            _Out_opt_ PFILETIME lpftLastWriteTime
        );

    DWORD
        ORAPI
        ORGetKeySecurity(
            _In_ ORHKEY Handle,
            _In_ SECURITY_INFORMATION SecurityInformation,
            _Out_opt_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
            _Inout_ PDWORD lpcbSecurityDescriptor
        );

    DWORD
        ORAPI
        ORSetKeySecurity(
            _In_ ORHKEY Handle,
            _In_ SECURITY_INFORMATION SecurityInformation,
            _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
        );

    DWORD
        ORAPI
        ORGetVirtualFlags(
            _In_ ORHKEY Handle,
            _Out_ PDWORD pdwFlags
        );

    DWORD
        ORAPI
        ORSetVirtualFlags(
            _In_ ORHKEY Handle,
            _In_ DWORD dwFlags
        );

    DWORD
        ORAPI
        ORDeleteValue(
            _In_ ORHKEY Handle,
            _In_opt_ PCWSTR lpValueName
        );

    DWORD
        ORAPI
        ORGetValue(
            _In_ ORHKEY Handle,
            _In_opt_ PCWSTR lpSubKey,
            _In_opt_ PCWSTR lpValue,
            _Out_opt_ PDWORD pdwType,
            _Out_writes_bytes_opt_(*pcbData) PVOID pvData,
            _Inout_opt_ PDWORD pcbData
        );

    DWORD
        ORAPI
        ORSetValue(
            _In_ ORHKEY Handle,
            _In_opt_ PCWSTR lpValueName,
            _In_ DWORD dwType,
            _In_reads_bytes_opt_(cbData) const BYTE* lpData,
            _In_ DWORD cbData
        );

    DWORD
        ORAPI
        OREnumValue(
            _In_ ORHKEY Handle,
            _In_ DWORD dwIndex,
            _Out_writes_(*lpcValueName) PWSTR lpValueName,
            _Inout_ PDWORD lpcValueName,
            _Out_opt_ PDWORD lpType,
            _Out_writes_bytes_opt_(*lpcbData) PBYTE lpData,
            _Inout_opt_ PDWORD lpcbData
        );

    DWORD
        ORAPI
        ORRenameKey(
            _In_ ORHKEY Handle,
            _In_ PCWSTR lpNewName
        );

    DWORD
        ORStart(
            VOID
        );

    VOID
        ORShutdown(
            VOID
        );

    DWORD
        ORAPI
        ORMergeHives(
            _In_reads_(HiveCount) ORHKEY* HiveHandles,
            _In_ ULONG HiveCount,
            _Out_ PORHKEY phkResult
        );

#ifdef __cplusplus
}
#endif

#endif //__OFFREG_H__
