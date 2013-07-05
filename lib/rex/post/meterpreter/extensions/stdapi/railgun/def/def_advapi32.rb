# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_advapi32

  CREDENTIAL = [
    [:Flags, :DWORD],
    [:Type, :DWORD],
    [:TargetName, :LPTSTR],
    [:Comment, :LPTSTR],
    [:LastWritten, :FILETIME],
    [:CredentialBlobSize, :DWORD],
    [:CredentialBlob, :LPBYTE],
    [:Persist, :DWORD],
    [:AttributeCount, :LPTSTR],
    [:Attributes, :PCREDENTIAL_ATTRIBUTE],
    [:TargetAlias, :LPTSTR],
    [:UserName, :LPTSTR]
  ]

  def self.create_dll(dll_path = 'advapi32')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function('QueryServiceStatus', 'DWORD', [
        ['LPVOID', 'hService', 'in'],
        ['BLOB', 'lpServiceStatus', 'out'])

    dll.add_function('CredEnumerateA', 'BOOL', [
        ['PCHAR', 'Filter', 'in'],
        ['DWORD', 'Flags', 'in'],
        ['PDWORD', 'Count', 'out'],
        ['PBLOB', 'Credentials', 'out']])

    #Functions for Windows CryptoAPI
    dll.add_function( 'CryptAcquireContextW', 'BOOL',[
        ['PDWORD', 'phProv', 'out'],
        ['PWCHAR', 'pszContainer', 'in'],
        ['PWCHAR', 'pszProvider', 'in'],
        ['DWORD', 'dwProvType', 'in'],
        ['DWORD', 'dwflags', 'in']])

    dll.add_function( 'CryptAcquireContextA', 'BOOL',[
        ['PDWORD', 'phProv', 'out'],
        ['PWCHAR', 'pszContainer', 'in'],
        ['PWCHAR', 'pszProvider', 'in'],
        ['DWORD', 'dwProvType', 'in'],
        ['DWORD', 'dwflags', 'in']])


    dll.add_function( 'CryptContextAddRef', 'BOOL', [
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptEnumProvidersW', 'BOOL', [
        ['DWORD', 'dwIndex', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'pdwProvType', 'out'],
        ['PWCHAR', 'pszProvName', 'out'],
        ['PDWORD', 'pcbProvName', 'inout']])

    dll.add_function( 'CryptEnumProvidersA', 'BOOL', [
        ['DWORD', 'dwIndex', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'pdwProvType', 'out'],
        ['PCHAR', 'pszProvName', 'out'],
        ['PDWORD', 'pcbProvName', 'inout']])

    dll.add_function( 'CryptEnumProviderTypesW', 'BOOL', [
        ['DWORD', 'dwIndex', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'pdwProvType', 'out'],
        ['PWCHAR', 'pszTypeName', 'out'],
        ['PDWORD', 'pcbTypeName', 'inout']])

    dll.add_function( 'CryptEnumProviderTypesA', 'BOOL', [
        ['DWORD', 'dwIndex', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'pdwProvType', 'out'],
        ['PCHAR', 'pszTypeName', 'out'],
        ['PDWORD', 'pcbTypeName', 'inout']])

    dll.add_function( 'CryptGetDefaultProviderW ', 'BOOL', [
        ['DWORD', 'dwProvType', 'in'],
        ['DWORD', 'pwdReserved', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PWCHAR', 'pszProvName', 'out'],
        ['PDWORD', 'pcbProvName', 'inout']])

    dll.add_function( 'CryptGetDefaultProviderA ', 'BOOL', [
        ['DWORD', 'dwProvType', 'in'],
        ['DWORD', 'pwdReserved', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PCHAR', 'pszProvName', 'out'],
        ['PDWORD', 'pcbProvName', 'inout']])

    dll.add_function( 'CryptGetProvParam', 'BOOL', [
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'dwParam', 'in'],
        ['PBLOB', 'pbData', 'out'],
        ['PDWORD', 'pwdDataLen', 'inout'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptSetProviderW', 'BOOL', [
        ['PWCHAR', 'pszProvName', 'in'],
        ['DWORD', 'dwProvType', 'in']])

    dll.add_function( 'CryptSetProviderA', 'BOOL', [
        ['PCHAR', 'pszProvName', 'in'],
        ['DWORD', 'dwProvType', 'in']])

    dll.add_function( 'CryptSetProviderExW', 'BOOL', [
        ['PWCHAR', 'pszProvName', 'in'],
        ['DWORD', 'dwProvType', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptSetProviderExA', 'BOOL', [
        ['PCHAR', 'pszProvName', 'in'],
        ['DWORD', 'dwProvType', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptSetProvParam', 'BOOL', [
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'dwParam', 'in'],
        ['PBLOB', 'pbData', 'in'],
        ['DWORD', 'dwFlags','in']])

    dll.add_function( 'CryptDuplicateKey', 'BOOL', [
        ['LPVOID', 'hKey', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'phKey', 'out']])

    dll.add_function( 'CryptExportKey', 'BOOL', [
        ['LPVOID', 'hKey', 'in'],
        ['LPVOID', 'hExpKey', 'in'],
        ['DWORD', 'dwBlobType', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PBLOB', 'pbData', 'out'],
        ['PDWORD', 'pwdDataLen', 'inout']])

    dll.add_function( 'CryptGenKey', 'BOOL', [
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'Algid', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'phKey', 'out']])

    dll.add_function( 'CryptGenRandom', 'BOOL', [
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'dwLen', 'in'],
        ['PBLOB', 'pbBuffer', 'inout']])

    dll.add_function( 'CryptGetKeyParam', 'BOOL', [
        ['LPVOID', 'hKey', 'in'],
        ['DWORD', 'dwParam', 'in'],
        ['PBLOB', 'pbData', 'out'],
        ['PDWORD', 'pdwDataLen',  'inout'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptGetUserKey', 'BOOL', [
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'dwKeySpec', 'in'],
        ['PDWORD', 'phUserKey', 'out']])

    dll.add_function( 'CryptImportKey', 'BOOL', [
        ['LPVOID', 'hProv', 'in'],
        ['PBLOB', 'pbData', 'in'],
        ['DWORD', 'dwDataLen', 'in'],
        ['LPVOID', 'hPubKey', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'phKey', 'out']])

    dll.add_function( 'CryptSetKeyParam', 'BOOL', [
        ['LPVOID', 'hKey', 'in'],
        ['DWORD', 'dwParam', 'in'],
        ['PBLOB', 'pbData', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptEncrypt', 'BOOL', [
        ['LPVOID', 'hKey', 'in'],
        ['LPVOID', 'hHash', 'in'],
        ['BOOL', 'Final', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PBLOB', 'pbData', 'inout'],
        ['PDWORD', 'pdwDataLen', 'inout'],
        ['DWORD', 'dwBufLen', 'in']])

    dll.add_function( 'CryptDuplicateHash', 'BOOL', [
        ['LPVOID', 'hHash', 'in'],
        ['DWORD', 'pdwReserved', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'phHash', 'out']])

    dll.add_function( 'CryptGetHashParam', 'BOOL', [
        ['LPVOID', 'hHash', 'in'],
        ['DWORD', 'dwParam', 'in'],
        ['PBLOB', 'pbData', 'out'],
        ['PDWORD', 'pdwDataLen', 'inout'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptHashSessionKey', 'BOOL', [
        ['LPVOID', 'hHash', 'in'],
        ['LPVOID', 'hKey', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptSetHashParam', 'BOOL', [
        ['LPVOID', 'hHash', 'in'],
        ['DWORD', 'dwParam', 'in'],
        ['PBLOB', 'pbData', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptSignHashW', 'BOOL', [
        ['LPVOID', 'hHash', 'in'],
        ['DWORD', 'dwKeySpec', 'in'],
        ['PWCHAR', 'sDescription', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PBLOB', 'pbSignature', 'out'],
        ['PDWORD', 'pdwSigLen', 'inout']])

    dll.add_function( 'CryptSignHashA', 'BOOL', [
        ['LPVOID', 'hHash', 'in'],
        ['DWORD', 'dwKeySpec', 'in'],
        ['PCHAR', 'sDescription', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PBLOB', 'pbSignature', 'out'],
        ['PDWORD', 'pdwSigLen', 'inout']])

    dll.add_function( 'CryptVerifySignatureW', 'BOOL', [
        ['LPVOID', 'hHash', 'in'],
        ['PBLOB', 'pbSignature', 'in'],
        ['DWORD', 'dwSigLen', 'in'],
        ['LPVOID', 'hPubKey', 'in'],
        ['PWCHAR', 'sDescription', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptVerifySignatureA', 'BOOL', [
        ['LPVOID', 'hHash', 'in'],
        ['PBLOB', 'pbSignature', 'in'],
        ['DWORD', 'dwSigLen', 'in'],
        ['LPVOID', 'hPubKey', 'in'],
        ['PCHAR', 'sDescription', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptCreateHash', 'BOOL',[
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'Algid', 'in'],
        ['LPVOID', 'hKey', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'phHash', 'out']])

    dll.add_function( 'CryptHashData', 'BOOL',[
        ['LPVOID', 'hHash', 'in'],
        ['PWCHAR', 'pbData', 'in'],
        ['DWORD', 'dwDataLen', 'in'],
        ['DWORD', 'dwFlags', 'in']])

    dll.add_function( 'CryptDeriveKey', 'BOOL',[
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'Algid', 'in'],
        ['LPVOID', 'hBaseData', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PDWORD', 'phKey', 'inout']])

    dll.add_function( 'CryptDecrypt', 'BOOL',[
        ['LPVOID', 'hKey', 'in'],
        ['LPVOID', 'hHash', 'in'],
        ['BOOL', 'Final', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PBLOB', 'pbData', 'inout'],
        ['PDWORD', 'pdwDataLen', 'inout']])

    dll.add_function( 'CryptDestroyHash', 'BOOL',[
        ['LPVOID', 'hHash', 'in']])

    dll.add_function( 'CryptDestroyKey', 'BOOL',[
        ['LPVOID', 'hKey', 'in']])

    dll.add_function( 'CryptReleaseContext', 'BOOL',[
        ['LPVOID', 'hProv', 'in'],
        ['DWORD', 'dwFlags', 'in']])


    # Function to open the Service Control Database
    dll.add_function('OpenSCManagerA','DWORD',[
      [ "PCHAR", "lpMachineName", "inout" ],
      [ "PCHAR", "lpDatabaseName", "inout" ],
      [ "DWORD", "dwDesiredAccess", "in" ]
      ])

    # Function for creating a Service
    dll.add_function('CreateServiceA','DWORD',[
      [ "DWORD", "hSCManager", "in" ],
      [ "PCHAR", "lpServiceName", "in" ],
      [ "PCHAR", "lpDisplayName", "in" ],
      [ "DWORD", "dwDesiredAccess", "in" ],
      [ "DWORD", "dwServiceType", "in" ],
      [ "DWORD", "dwStartType", "in" ],
      [ "DWORD", "dwErrorControl", "in" ],
      [ "PCHAR", "lpBinaryPathName", "in" ],
      [ "PCHAR", "lpLoadOrderGroup", "in" ],
      [ "PDWORD", "lpdwTagId", "out" ],
      [ "PCHAR", "lpDependencies", "in" ],
      [ "PCHAR", "lpServiceStartName", "in" ],
      [ "PCHAR", "lpPassword", "in" ]
      ])

    dll.add_function('OpenServiceA','DWORD',[
      [ "DWORD", "hSCManager", "in" ],
      [ "PCHAR", "lpServiceName", "in" ],
      [ "DWORD", "dwDesiredAccess", "in" ]
      ])

    #access rights: SERVICE_CHANGE_CONFIG (0x0002)  SERVICE_START (0x0010)
    #SERVICE_STOP (0x0020)

    dll.add_function('StartServiceA','BOOL',[
      [ "DWORD", "hService", "in" ],
      [ "DWORD", "dwNumServiceArgs", "in" ],
      [ "PCHAR", "lpServiceArgVectors", "in" ]
      ])

    dll.add_function('ControlService','BOOL',[
      [ "DWORD", "hService", "in" ],
      [ "DWORD", "dwControl", "in" ],
      [ "PBLOB", "lpServiceStatus", "out" ]
      ])

    #SERVICE_CONTROL_STOP = 0x00000001

    # _SERVICE_STATUS  is an array of 7 DWORDS -  dwServiceType;
    #dwCurrentState; dwControlsAccepted; dwWin32ExitCode;
    #dwServiceSpecificExitCode; dwCheckPoint; dwWaitHint;

    dll.add_function('ChangeServiceConfigA','BOOL',[
      [ "DWORD", "hService", "in" ],
      [ "DWORD", "dwServiceType", "in" ],
      [ "DWORD", "dwStartType", "in" ],
      [ "DWORD", "dwErrorControl", "in" ],
      [ "PCHAR", "lpBinaryPathName", "in" ],
      [ "PCHAR", "lpLoadOrderGroup", "in" ],
      [ "PDWORD", "lpdwTagId", "out" ],
      [ "PCHAR", "lpDependencies", "in" ],
      [ "PCHAR", "lpServiceStartName", "in" ],
      [ "PCHAR", "lpPassword", "in" ],
      [ "PCHAR", "lpDisplayName", "in" ]
      ])

    dll.add_function('CloseServiceHandle','BOOL',[
      [ "DWORD", "hSCObject", "in" ]
      ])

    dll.add_function('DeleteService','BOOL',[
      [ "DWORD", "hService", "in" ]
      ])

    dll.add_function('AbortSystemShutdownA', 'BOOL',[
      ["PCHAR","lpMachineName","in"],
      ])

    dll.add_function('AbortSystemShutdownW', 'BOOL',[
      ["PWCHAR","lpMachineName","in"],
      ])

    dll.add_function('InitiateSystemShutdownA', 'BOOL',[
      ["PCHAR","lpMachineName","in"],
      ["PCHAR","lpMessage","in"],
      ["DWORD","dwTimeout","in"],
      ["BOOL","bForceAppsClosed","in"],
      ["BOOL","bRebootAfterShutdown","in"],
      ])

    dll.add_function('InitiateSystemShutdownExA', 'BOOL',[
      ["PCHAR","lpMachineName","in"],
      ["PCHAR","lpMessage","in"],
      ["DWORD","dwTimeout","in"],
      ["BOOL","bForceAppsClosed","in"],
      ["BOOL","bRebootAfterShutdown","in"],
      ["DWORD","dwReason","in"],
      ])

    dll.add_function('InitiateSystemShutdownExW', 'BOOL',[
      ["PWCHAR","lpMachineName","in"],
      ["PWCHAR","lpMessage","in"],
      ["DWORD","dwTimeout","in"],
      ["BOOL","bForceAppsClosed","in"],
      ["BOOL","bRebootAfterShutdown","in"],
      ["DWORD","dwReason","in"],
      ])

    dll.add_function('InitiateSystemShutdownW', 'BOOL',[
      ["PWCHAR","lpMachineName","in"],
      ["PWCHAR","lpMessage","in"],
      ["DWORD","dwTimeout","in"],
      ["BOOL","bForceAppsClosed","in"],
      ["BOOL","bRebootAfterShutdown","in"],
      ])

    dll.add_function('RegCloseKey', 'DWORD',[
      ["DWORD","hKey","in"],
      ])

    dll.add_function('RegConnectRegistryA', 'DWORD',[
      ["PCHAR","lpMachineName","in"],
      ["DWORD","hKey","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegConnectRegistryExA', 'DWORD',[
      ["PCHAR","lpMachineName","in"],
      ["DWORD","hKey","in"],
      ["DWORD","Flags","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegConnectRegistryExW', 'DWORD',[
      ["PWCHAR","lpMachineName","in"],
      ["DWORD","hKey","in"],
      ["DWORD","Flags","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegConnectRegistryW', 'DWORD',[
      ["PWCHAR","lpMachineName","in"],
      ["DWORD","hKey","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegCreateKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegCreateKeyExA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["DWORD","Reserved","inout"],
      ["PCHAR","lpClass","in"],
      ["DWORD","dwOptions","in"],
      ["DWORD","samDesired","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ["PDWORD","phkResult","out"],
      ["PDWORD","lpdwDisposition","out"],
      ])

    dll.add_function('RegCreateKeyExW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["DWORD","Reserved","inout"],
      ["PWCHAR","lpClass","in"],
      ["DWORD","dwOptions","in"],
      ["DWORD","samDesired","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ["PDWORD","phkResult","out"],
      ["PDWORD","lpdwDisposition","out"],
      ])

    dll.add_function('RegCreateKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegDeleteKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ])

    dll.add_function('RegDeleteKeyExA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["DWORD","samDesired","in"],
      ["DWORD","Reserved","inout"],
      ])

    dll.add_function('RegDeleteKeyExW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["DWORD","samDesired","in"],
      ["DWORD","Reserved","inout"],
      ])

    dll.add_function('RegDeleteKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ])

    dll.add_function('RegDeleteValueA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpValueName","in"],
      ])

    dll.add_function('RegDeleteValueW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpValueName","in"],
      ])

    dll.add_function('RegDisablePredefinedCache', 'DWORD',[
      ])

    dll.add_function('RegDisableReflectionKey', 'DWORD',[
      ["DWORD","hBase","in"],
      ])

    dll.add_function('RegEnableReflectionKey', 'DWORD',[
      ["DWORD","hBase","in"],
      ])

    dll.add_function('RegEnumKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["DWORD","dwIndex","in"],
      ["PCHAR","lpName","out"],
      ["DWORD","cchName","in"],
      ])

    dll.add_function('RegEnumKeyExA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["DWORD","dwIndex","in"],
      ["PCHAR","lpName","out"],
      ["PDWORD","lpcchName","inout"],
      ["PDWORD","lpReserved","inout"],
      ["PCHAR","lpClass","inout"],
      ["PDWORD","lpcchClass","inout"],
      ["PBLOB","lpftLastWriteTime","out"],
      ])

    dll.add_function('RegEnumKeyExW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["DWORD","dwIndex","in"],
      ["PWCHAR","lpName","out"],
      ["PDWORD","lpcchName","inout"],
      ["PDWORD","lpReserved","inout"],
      ["PWCHAR","lpClass","inout"],
      ["PDWORD","lpcchClass","inout"],
      ["PBLOB","lpftLastWriteTime","out"],
      ])

    dll.add_function('RegEnumKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["DWORD","dwIndex","in"],
      ["PWCHAR","lpName","out"],
      ["DWORD","cchName","in"],
      ])

    dll.add_function('RegEnumValueA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["DWORD","dwIndex","in"],
      ["PCHAR","lpValueName","out"],
      ["PDWORD","lpcchValueName","inout"],
      ["PDWORD","lpReserved","inout"],
      ["PDWORD","lpType","out"],
      ["PBLOB","lpData","out"],
      ["PDWORD","lpcbData","inout"],
      ])

    dll.add_function('RegEnumValueW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["DWORD","dwIndex","in"],
      ["PWCHAR","lpValueName","out"],
      ["PDWORD","lpcchValueName","inout"],
      ["PDWORD","lpReserved","inout"],
      ["PDWORD","lpType","out"],
      ["PBLOB","lpData","out"],
      ["PDWORD","lpcbData","inout"],
      ])

    dll.add_function('RegFlushKey', 'DWORD',[
      ["DWORD","hKey","in"],
      ])

    dll.add_function('RegGetKeySecurity', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PBLOB","SecurityInformation","in"],
      ["PBLOB","pSecurityDescriptor","out"],
      ["PDWORD","lpcbSecurityDescriptor","inout"],
      ])

    dll.add_function('RegGetValueA', 'DWORD',[
      ["DWORD","hkey","in"],
      ["PCHAR","lpSubKey","in"],
      ["PCHAR","lpValue","in"],
      ["DWORD","dwFlags","in"],
      ["PDWORD","pdwType","out"],
      ["PBLOB","pvData","out"],
      ["PDWORD","pcbData","inout"],
      ])

    dll.add_function('RegGetValueW', 'DWORD',[
      ["DWORD","hkey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["PWCHAR","lpValue","in"],
      ["DWORD","dwFlags","in"],
      ["PDWORD","pdwType","out"],
      ["PBLOB","pvData","out"],
      ["PDWORD","pcbData","inout"],
      ])

    dll.add_function('RegLoadKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["PCHAR","lpFile","in"],
      ])

    dll.add_function('RegLoadKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["PWCHAR","lpFile","in"],
      ])

    dll.add_function('RegNotifyChangeKeyValue', 'DWORD',[
      ["DWORD","hKey","in"],
      ["BOOL","bWatchSubtree","in"],
      ["DWORD","dwNotifyFilter","in"],
      ["DWORD","hEvent","in"],
      ["BOOL","fAsynchronous","in"],
      ])

    dll.add_function('RegOpenCurrentUser', 'DWORD',[
      ["DWORD","samDesired","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegOpenKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegOpenKeyExA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["DWORD","ulOptions","inout"],
      ["DWORD","samDesired","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegOpenKeyExW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["DWORD","ulOptions","inout"],
      ["DWORD","samDesired","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegOpenKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegOpenUserClassesRoot', 'DWORD',[
      ["DWORD","hToken","in"],
      ["DWORD","dwOptions","inout"],
      ["DWORD","samDesired","in"],
      ["PDWORD","phkResult","out"],
      ])

    dll.add_function('RegOverridePredefKey', 'DWORD',[
      ["DWORD","hKey","in"],
      ["DWORD","hNewHKey","in"],
      ])

    dll.add_function('RegQueryInfoKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpClass","out"],
      ["PDWORD","lpcchClass","inout"],
      ["PDWORD","lpReserved","inout"],
      ["PDWORD","lpcSubKeys","out"],
      ["PDWORD","lpcbMaxSubKeyLen","out"],
      ["PDWORD","lpcbMaxClassLen","out"],
      ["PDWORD","lpcValues","out"],
      ["PDWORD","lpcbMaxValueNameLen","out"],
      ["PDWORD","lpcbMaxValueLen","out"],
      ["PDWORD","lpcbSecurityDescriptor","out"],
      ["PBLOB","lpftLastWriteTime","out"],
      ])

    dll.add_function('RegQueryInfoKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpClass","out"],
      ["PDWORD","lpcchClass","inout"],
      ["PDWORD","lpReserved","inout"],
      ["PDWORD","lpcSubKeys","out"],
      ["PDWORD","lpcbMaxSubKeyLen","out"],
      ["PDWORD","lpcbMaxClassLen","out"],
      ["PDWORD","lpcValues","out"],
      ["PDWORD","lpcbMaxValueNameLen","out"],
      ["PDWORD","lpcbMaxValueLen","out"],
      ["PDWORD","lpcbSecurityDescriptor","out"],
      ["PBLOB","lpftLastWriteTime","out"],
      ])

    dll.add_function('RegQueryMultipleValuesA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PBLOB","val_list","out"],
      ["DWORD","num_vals","in"],
      ["PCHAR","lpValueBuf","out"],
      ["PDWORD","ldwTotsize","inout"],
      ])

    dll.add_function('RegQueryMultipleValuesW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PBLOB","val_list","out"],
      ["DWORD","num_vals","in"],
      ["PWCHAR","lpValueBuf","out"],
      ["PDWORD","ldwTotsize","inout"],
      ])

    dll.add_function('RegQueryReflectionKey', 'DWORD',[
      ["DWORD","hBase","in"],
      ["PBLOB","bIsReflectionDisabled","out"],
      ])

    dll.add_function('RegQueryValueA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["PCHAR","lpData","out"],
      ["PDWORD","lpcbData","inout"],
      ])

    dll.add_function('RegQueryValueExA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpValueName","in"],
      ["PDWORD","lpReserved","inout"],
      ["PDWORD","lpType","out"],
      ["PBLOB","lpData","out"],
      ["PDWORD","lpcbData","inout"],
      ])

    dll.add_function('RegQueryValueExW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpValueName","in"],
      ["PDWORD","lpReserved","inout"],
      ["PDWORD","lpType","out"],
      ["PBLOB","lpData","out"],
      ["PDWORD","lpcbData","inout"],
      ])

    dll.add_function('RegQueryValueW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["PWCHAR","lpData","out"],
      ["PDWORD","lpcbData","inout"],
      ])

    dll.add_function('RegReplaceKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["PCHAR","lpNewFile","in"],
      ["PCHAR","lpOldFile","in"],
      ])

    dll.add_function('RegReplaceKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["PWCHAR","lpNewFile","in"],
      ["PWCHAR","lpOldFile","in"],
      ])

    dll.add_function('RegRestoreKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpFile","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('RegRestoreKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpFile","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('RegSaveKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpFile","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function('RegSaveKeyExA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpFile","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('RegSaveKeyExW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpFile","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('RegSaveKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpFile","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function('RegSetKeySecurity', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PBLOB","SecurityInformation","in"],
      ["PBLOB","pSecurityDescriptor","in"],
      ])

    dll.add_function('RegSetValueA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ["DWORD","dwType","in"],
      ["PCHAR","lpData","in"],
      ["DWORD","cbData","in"],
      ])

    dll.add_function('RegSetValueExA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpValueName","in"],
      ["DWORD","Reserved","inout"],
      ["DWORD","dwType","in"],
      ["PBLOB","lpData","in"],
      ["DWORD","cbData","in"],
      ])

    dll.add_function('RegSetValueExW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpValueName","in"],
      ["DWORD","Reserved","inout"],
      ["DWORD","dwType","in"],
      ["PBLOB","lpData","in"],
      ["DWORD","cbData","in"],
      ])

    dll.add_function('RegSetValueW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ["DWORD","dwType","in"],
      ["PWCHAR","lpData","in"],
      ["DWORD","cbData","in"],
      ])

    dll.add_function('RegUnLoadKeyA', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PCHAR","lpSubKey","in"],
      ])

    dll.add_function('RegUnLoadKeyW', 'DWORD',[
      ["DWORD","hKey","in"],
      ["PWCHAR","lpSubKey","in"],
      ])

    dll.add_function('Wow64Win32ApiEntry', 'DWORD',[
      ["DWORD","dwFuncNumber","in"],
      ["DWORD","dwFlag","in"],
      ["DWORD","dwRes","in"],
      ])

    dll.add_function('AccessCheck', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["DWORD","ClientToken","in"],
      ["DWORD","DesiredAccess","in"],
      ["PBLOB","GenericMapping","in"],
      ["PBLOB","PrivilegeSet","out"],
      ["PDWORD","PrivilegeSetLength","inout"],
      ["PDWORD","GrantedAccess","out"],
      ["PBLOB","AccessStatus","out"],
      ])

    dll.add_function('AccessCheckAndAuditAlarmA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["PCHAR","ObjectTypeName","in"],
      ["PCHAR","ObjectName","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ["DWORD","DesiredAccess","in"],
      ["PBLOB","GenericMapping","in"],
      ["BOOL","ObjectCreation","in"],
      ["PDWORD","GrantedAccess","out"],
      ["PBLOB","AccessStatus","out"],
      ["PBLOB","pfGenerateOnClose","out"],
      ])

    dll.add_function('AccessCheckAndAuditAlarmW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["PWCHAR","ObjectTypeName","in"],
      ["PWCHAR","ObjectName","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ["DWORD","DesiredAccess","in"],
      ["PBLOB","GenericMapping","in"],
      ["BOOL","ObjectCreation","in"],
      ["PDWORD","GrantedAccess","out"],
      ["PBLOB","AccessStatus","out"],
      ["PBLOB","pfGenerateOnClose","out"],
      ])

    dll.add_function('AccessCheckByType', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["LPVOID","PrincipalSelfSid","in"],
      ["DWORD","ClientToken","in"],
      ["DWORD","DesiredAccess","in"],
      ["PBLOB","ObjectTypeList","inout"],
      ["DWORD","ObjectTypeListLength","in"],
      ["PBLOB","GenericMapping","in"],
      ["PBLOB","PrivilegeSet","out"],
      ["PDWORD","PrivilegeSetLength","inout"],
      ["PDWORD","GrantedAccess","out"],
      ["PBLOB","AccessStatus","out"],
      ])

    dll.add_function('AccessCheckByTypeAndAuditAlarmA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["PCHAR","ObjectTypeName","in"],
      ["PCHAR","ObjectName","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ["LPVOID","PrincipalSelfSid","in"],
      ["DWORD","DesiredAccess","in"],
      ["DWORD","AuditType","in"],
      ["DWORD","Flags","in"],
      ["PBLOB","ObjectTypeList","inout"],
      ["DWORD","ObjectTypeListLength","in"],
      ["PBLOB","GenericMapping","in"],
      ["BOOL","ObjectCreation","in"],
      ["PDWORD","GrantedAccess","out"],
      ["PBLOB","AccessStatus","out"],
      ["PBLOB","pfGenerateOnClose","out"],
      ])

    dll.add_function('AccessCheckByTypeAndAuditAlarmW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["PWCHAR","ObjectTypeName","in"],
      ["PWCHAR","ObjectName","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ["LPVOID","PrincipalSelfSid","in"],
      ["DWORD","DesiredAccess","in"],
      ["DWORD","AuditType","in"],
      ["DWORD","Flags","in"],
      ["PBLOB","ObjectTypeList","inout"],
      ["DWORD","ObjectTypeListLength","in"],
      ["PBLOB","GenericMapping","in"],
      ["BOOL","ObjectCreation","in"],
      ["PDWORD","GrantedAccess","out"],
      ["PBLOB","AccessStatus","out"],
      ["PBLOB","pfGenerateOnClose","out"],
      ])

    dll.add_function('AccessCheckByTypeResultList', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["LPVOID","PrincipalSelfSid","in"],
      ["DWORD","ClientToken","in"],
      ["DWORD","DesiredAccess","in"],
      ["PBLOB","ObjectTypeList","inout"],
      ["DWORD","ObjectTypeListLength","in"],
      ["PBLOB","GenericMapping","in"],
      ["PBLOB","PrivilegeSet","out"],
      ["PDWORD","PrivilegeSetLength","inout"],
      ["PDWORD","GrantedAccessList","out"],
      ["PDWORD","AccessStatusList","out"],
      ])

    dll.add_function('AccessCheckByTypeResultListAndAuditAlarmA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["PCHAR","ObjectTypeName","in"],
      ["PCHAR","ObjectName","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ["LPVOID","PrincipalSelfSid","in"],
      ["DWORD","DesiredAccess","in"],
      ["DWORD","AuditType","in"],
      ["DWORD","Flags","in"],
      ["PBLOB","ObjectTypeList","inout"],
      ["DWORD","ObjectTypeListLength","in"],
      ["PBLOB","GenericMapping","in"],
      ["BOOL","ObjectCreation","in"],
      ["PDWORD","GrantedAccess","out"],
      ["PDWORD","AccessStatusList","out"],
      ["PBLOB","pfGenerateOnClose","out"],
      ])

    dll.add_function('AccessCheckByTypeResultListAndAuditAlarmByHandleA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["DWORD","ClientToken","in"],
      ["PCHAR","ObjectTypeName","in"],
      ["PCHAR","ObjectName","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ["LPVOID","PrincipalSelfSid","in"],
      ["DWORD","DesiredAccess","in"],
      ["DWORD","AuditType","in"],
      ["DWORD","Flags","in"],
      ["PBLOB","ObjectTypeList","inout"],
      ["DWORD","ObjectTypeListLength","in"],
      ["PBLOB","GenericMapping","in"],
      ["BOOL","ObjectCreation","in"],
      ["PDWORD","GrantedAccess","out"],
      ["PDWORD","AccessStatusList","out"],
      ["PBLOB","pfGenerateOnClose","out"],
      ])

    dll.add_function('AccessCheckByTypeResultListAndAuditAlarmByHandleW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["DWORD","ClientToken","in"],
      ["PWCHAR","ObjectTypeName","in"],
      ["PWCHAR","ObjectName","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ["LPVOID","PrincipalSelfSid","in"],
      ["DWORD","DesiredAccess","in"],
      ["DWORD","AuditType","in"],
      ["DWORD","Flags","in"],
      ["PBLOB","ObjectTypeList","inout"],
      ["DWORD","ObjectTypeListLength","in"],
      ["PBLOB","GenericMapping","in"],
      ["BOOL","ObjectCreation","in"],
      ["PDWORD","GrantedAccess","out"],
      ["PDWORD","AccessStatusList","out"],
      ["PBLOB","pfGenerateOnClose","out"],
      ])

    dll.add_function('AccessCheckByTypeResultListAndAuditAlarmW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["PWCHAR","ObjectTypeName","in"],
      ["PWCHAR","ObjectName","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ["LPVOID","PrincipalSelfSid","in"],
      ["DWORD","DesiredAccess","in"],
      ["DWORD","AuditType","in"],
      ["DWORD","Flags","in"],
      ["PBLOB","ObjectTypeList","inout"],
      ["DWORD","ObjectTypeListLength","in"],
      ["PBLOB","GenericMapping","in"],
      ["BOOL","ObjectCreation","in"],
      ["PDWORD","GrantedAccess","out"],
      ["PDWORD","AccessStatusList","out"],
      ["PBLOB","pfGenerateOnClose","out"],
      ])

    dll.add_function('AddAccessAllowedAce', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","AccessMask","in"],
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('AddAccessAllowedAceEx', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","AceFlags","in"],
      ["DWORD","AccessMask","in"],
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('AddAccessAllowedObjectAce', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","AceFlags","in"],
      ["DWORD","AccessMask","in"],
      ["PBLOB","ObjectTypeGuid","in"],
      ["PBLOB","InheritedObjectTypeGuid","in"],
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('AddAccessDeniedAce', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","AccessMask","in"],
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('AddAccessDeniedAceEx', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","AceFlags","in"],
      ["DWORD","AccessMask","in"],
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('AddAccessDeniedObjectAce', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","AceFlags","in"],
      ["DWORD","AccessMask","in"],
      ["PBLOB","ObjectTypeGuid","in"],
      ["PBLOB","InheritedObjectTypeGuid","in"],
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('AddAce', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","dwStartingAceIndex","in"],
      ["PBLOB","pAceList","in"],
      ["DWORD","nAceListLength","in"],
      ])

    dll.add_function('AddAuditAccessAce', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","dwAccessMask","in"],
      ["LPVOID","pSid","in"],
      ["BOOL","bAuditSuccess","in"],
      ["BOOL","bAuditFailure","in"],
      ])

    dll.add_function('AddAuditAccessAceEx', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","AceFlags","in"],
      ["DWORD","dwAccessMask","in"],
      ["LPVOID","pSid","in"],
      ["BOOL","bAuditSuccess","in"],
      ["BOOL","bAuditFailure","in"],
      ])

    dll.add_function('AddAuditAccessObjectAce', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceRevision","in"],
      ["DWORD","AceFlags","in"],
      ["DWORD","AccessMask","in"],
      ["PBLOB","ObjectTypeGuid","in"],
      ["PBLOB","InheritedObjectTypeGuid","in"],
      ["LPVOID","pSid","in"],
      ["BOOL","bAuditSuccess","in"],
      ["BOOL","bAuditFailure","in"],
      ])

    dll.add_function('AdjustTokenGroups', 'BOOL',[
      ["DWORD","TokenHandle","in"],
      ["BOOL","ResetToDefault","in"],
      ["PBLOB","NewState","in"],
      ["DWORD","BufferLength","in"],
      ["PBLOB","PreviousState","out"],
      ["PDWORD","ReturnLength","out"],
      ])

    dll.add_function('AdjustTokenPrivileges', 'BOOL',[
      ["DWORD","TokenHandle","in"],
      ["BOOL","DisableAllPrivileges","in"],
      ["PBLOB","NewState","in"],
      ["DWORD","BufferLength","in"],
      ["PBLOB","PreviousState","out"],
      ["PDWORD","ReturnLength","out"],
      ])

    dll.add_function('AllocateAndInitializeSid', 'BOOL',[
      ["PBLOB","pIdentifierAuthority","in"],
      ["BYTE","nSubAuthorityCount","in"],
      ["DWORD","nSubAuthority0","in"],
      ["DWORD","nSubAuthority1","in"],
      ["DWORD","nSubAuthority2","in"],
      ["DWORD","nSubAuthority3","in"],
      ["DWORD","nSubAuthority4","in"],
      ["DWORD","nSubAuthority5","in"],
      ["DWORD","nSubAuthority6","in"],
      ["DWORD","nSubAuthority7","in"],
      ["PDWORD","pSid","out"],
      ])

    dll.add_function('AllocateLocallyUniqueId', 'BOOL',[
      ["PBLOB","Luid","out"],
      ])

    dll.add_function('AreAllAccessesGranted', 'BOOL',[
      ["DWORD","GrantedAccess","in"],
      ["DWORD","DesiredAccess","in"],
      ])

    dll.add_function('AreAnyAccessesGranted', 'BOOL',[
      ["DWORD","GrantedAccess","in"],
      ["DWORD","DesiredAccess","in"],
      ])

    dll.add_function('BackupEventLogA', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["PCHAR","lpBackupFileName","in"],
      ])

    dll.add_function('BackupEventLogW', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["PWCHAR","lpBackupFileName","in"],
      ])

    dll.add_function('CheckTokenMembership', 'BOOL',[
      ["DWORD","TokenHandle","in"],
      ["PBLOB","SidToCheck","in"],
      ["PBLOB","IsMember","out"],
      ])

    dll.add_function('ClearEventLogA', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["PCHAR","lpBackupFileName","in"],
      ])

    dll.add_function('ClearEventLogW', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["PWCHAR","lpBackupFileName","in"],
      ])

    dll.add_function('CloseEncryptedFileRaw', 'VOID',[
      ["PBLOB","pvContext","in"],
      ])

    dll.add_function('CloseEventLog', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ])

    dll.add_function('ConvertToAutoInheritPrivateObjectSecurity', 'BOOL',[
      ["PBLOB","ParentDescriptor","in"],
      ["PBLOB","CurrentSecurityDescriptor","in"],
      ["PBLOB","NewSecurityDescriptor","out"],
      ["PBLOB","ObjectType","in"],
      ["BOOL","IsDirectoryObject","in"],
      ["PBLOB","GenericMapping","in"],
      ])

    dll.add_function('ConvertStringSidToSidA', 'BOOL',[
      ["PCHAR","StringSid","in"],
      ["PDWORD","pSid","out"],
      ])

    dll.add_function('ConvertStringSidToSidW', 'BOOL',[
      ["PWCHAR","StringSid","in"],
      ["PDWORD","pSid","out"],
      ])

    dll.add_function('CopySid', 'BOOL',[
      ["DWORD","nDestinationSidLength","in"],
      ["PBLOB","pDestinationSid","out"],
      ["LPVOID","pSourceSid","in"],
      ])

    dll.add_function('CreatePrivateObjectSecurity', 'BOOL',[
      ["PBLOB","ParentDescriptor","in"],
      ["PBLOB","CreatorDescriptor","in"],
      ["PBLOB","NewDescriptor","out"],
      ["BOOL","IsDirectoryObject","in"],
      ["DWORD","Token","in"],
      ["PBLOB","GenericMapping","in"],
      ])

    dll.add_function('CreatePrivateObjectSecurityEx', 'BOOL',[
      ["PBLOB","ParentDescriptor","in"],
      ["PBLOB","CreatorDescriptor","in"],
      ["PBLOB","NewDescriptor","out"],
      ["PBLOB","ObjectType","in"],
      ["BOOL","IsContainerObject","in"],
      ["DWORD","AutoInheritFlags","in"],
      ["DWORD","Token","in"],
      ["PBLOB","GenericMapping","in"],
      ])

    dll.add_function('CreatePrivateObjectSecurityWithMultipleInheritance', 'BOOL',[
      ["PBLOB","ParentDescriptor","in"],
      ["PBLOB","CreatorDescriptor","in"],
      ["PBLOB","NewDescriptor","out"],
      ["PBLOB","ObjectTypes","in"],
      ["DWORD","GuidCount","in"],
      ["BOOL","IsContainerObject","in"],
      ["DWORD","AutoInheritFlags","in"],
      ["DWORD","Token","in"],
      ["PBLOB","GenericMapping","in"],
      ])

    dll.add_function('CreateProcessAsUserA', 'BOOL',[
      ["DWORD","hToken","in"],
      ["PCHAR","lpApplicationName","in"],
      ["PCHAR","lpCommandLine","inout"],
      ["PBLOB","lpProcessAttributes","in"],
      ["PBLOB","lpThreadAttributes","in"],
      ["BOOL","bInheritHandles","in"],
      ["DWORD","dwCreationFlags","in"],
      ["PBLOB","lpEnvironment","in"],
      ["PCHAR","lpCurrentDirectory","in"],
      ["PBLOB","lpStartupInfo","in"],
      ["PBLOB","lpProcessInformation","out"],
      ])

    dll.add_function('CreateProcessAsUserW', 'BOOL',[
      ["DWORD","hToken","in"],
      ["PWCHAR","lpApplicationName","in"],
      ["PWCHAR","lpCommandLine","inout"],
      ["PBLOB","lpProcessAttributes","in"],
      ["PBLOB","lpThreadAttributes","in"],
      ["BOOL","bInheritHandles","in"],
      ["DWORD","dwCreationFlags","in"],
      ["PBLOB","lpEnvironment","in"],
      ["PWCHAR","lpCurrentDirectory","in"],
      ["PBLOB","lpStartupInfo","in"],
      ["PBLOB","lpProcessInformation","out"],
      ])

    dll.add_function('CreateProcessWithLogonW', 'BOOL',[
      ["PWCHAR","lpUsername","in"],
      ["PWCHAR","lpDomain","in"],
      ["PWCHAR","lpPassword","in"],
      ["DWORD","dwLogonFlags","in"],
      ["PWCHAR","lpApplicationName","in"],
      ["PWCHAR","lpCommandLine","inout"],
      ["DWORD","dwCreationFlags","in"],
      ["PBLOB","lpEnvironment","in"],
      ["PWCHAR","lpCurrentDirectory","in"],
      ["PBLOB","lpStartupInfo","in"],
      ["PBLOB","lpProcessInformation","out"],
      ])

    dll.add_function('CreateProcessWithTokenW', 'BOOL',[
      ["DWORD","hToken","in"],
      ["DWORD","dwLogonFlags","in"],
      ["PWCHAR","lpApplicationName","in"],
      ["PWCHAR","lpCommandLine","inout"],
      ["DWORD","dwCreationFlags","in"],
      ["PBLOB","lpEnvironment","in"],
      ["PWCHAR","lpCurrentDirectory","in"],
      ["PBLOB","lpStartupInfo","in"],
      ["PBLOB","lpProcessInformation","out"],
      ])

    dll.add_function('CreateRestrictedToken', 'BOOL',[
      ["DWORD","ExistingTokenHandle","in"],
      ["DWORD","Flags","in"],
      ["DWORD","DisableSidCount","in"],
      ["PBLOB","SidsToDisable","in"],
      ["DWORD","DeletePrivilegeCount","in"],
      ["PBLOB","PrivilegesToDelete","in"],
      ["DWORD","RestrictedSidCount","in"],
      ["PBLOB","SidsToRestrict","in"],
      ["PDWORD","NewTokenHandle","out"],
      ])

    dll.add_function('CreateWellKnownSid', 'BOOL',[
      ["DWORD","WellKnownSidType","in"],
      ["PBLOB","DomainSid","in"],
      ["PBLOB","pSid","out"],
      ["PDWORD","cbSid","inout"],
      ])

    dll.add_function('DecryptFileA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ["DWORD","dwReserved","inout"],
      ])

    dll.add_function('DecryptFileW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ["DWORD","dwReserved","inout"],
      ])

    dll.add_function('DeleteAce', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["DWORD","dwAceIndex","in"],
      ])

    dll.add_function('DeregisterEventSource', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ])

    dll.add_function('DestroyPrivateObjectSecurity', 'BOOL',[
      ["PBLOB","ObjectDescriptor","in"],
      ])

    dll.add_function('DuplicateToken', 'BOOL',[
      ["DWORD","ExistingTokenHandle","in"],
      ["DWORD","ImpersonationLevel","in"],
      ["PDWORD","DuplicateTokenHandle","out"],
      ])

    dll.add_function('DuplicateTokenEx', 'BOOL',[
      ["DWORD","hExistingToken","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["PBLOB","lpTokenAttributes","in"],
      ["DWORD","ImpersonationLevel","in"],
      ["DWORD","TokenType","in"],
      ["PDWORD","phNewToken","out"],
      ])

    dll.add_function('EncryptFileA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function('EncryptFileW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function('EqualDomainSid', 'BOOL',[
      ["LPVOID","pSid1","in"],
      ["LPVOID","pSid2","in"],
      ["PBLOB","pfEqual","out"],
      ])

    dll.add_function('EqualPrefixSid', 'BOOL',[
      ["LPVOID","pSid1","in"],
      ["LPVOID","pSid2","in"],
      ])

    dll.add_function('EqualSid', 'BOOL',[
      ["LPVOID","pSid1","in"],
      ["LPVOID","pSid2","in"],
      ])

    dll.add_function('FileEncryptionStatusA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ["PDWORD","lpStatus","out"],
      ])

    dll.add_function('FileEncryptionStatusW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ["PDWORD","lpStatus","out"],
      ])

    dll.add_function('FindFirstFreeAce', 'BOOL',[
      ["PBLOB","pAcl","in"],
      ["PBLOB","pAce","out"],
      ])

    dll.add_function('FreeSid', 'LPVOID',[
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('GetAce', 'BOOL',[
      ["PBLOB","pAcl","in"],
      ["DWORD","dwAceIndex","in"],
      ["PBLOB","pAce","out"],
      ])

    dll.add_function('GetAclInformation', 'BOOL',[
      ["PBLOB","pAcl","in"],
      ["PBLOB","pAclInformation","out"],
      ["DWORD","nAclInformationLength","in"],
      ["DWORD","dwAclInformationClass","in"],
      ])

    dll.add_function('GetCurrentHwProfileA', 'BOOL',[
      ["PBLOB","lpHwProfileInfo","out"],
      ])

    dll.add_function('GetCurrentHwProfileW', 'BOOL',[
      ["PBLOB","lpHwProfileInfo","out"],
      ])

    dll.add_function('GetEventLogInformation', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["DWORD","dwInfoLevel","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","cbBufSize","in"],
      ["PDWORD","pcbBytesNeeded","out"],
      ])

    dll.add_function('GetFileSecurityA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ["DWORD","RequestedInformation","in"],
      ["PBLOB","pSecurityDescriptor","out"],
      ["DWORD","nLength","in"],
      ["PDWORD","lpnLengthNeeded","out"],
      ])

    dll.add_function('GetFileSecurityW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ["DWORD","RequestedInformation","in"],
      ["PBLOB","pSecurityDescriptor","out"],
      ["DWORD","nLength","in"],
      ["PDWORD","lpnLengthNeeded","out"],
      ])

    dll.add_function('GetKernelObjectSecurity', 'BOOL',[
      ["DWORD","Handle","in"],
      ["PBLOB","RequestedInformation","in"],
      ["PBLOB","pSecurityDescriptor","out"],
      ["DWORD","nLength","in"],
      ["PDWORD","lpnLengthNeeded","out"],
      ])

    dll.add_function('GetLengthSid', 'DWORD',[
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('GetNumberOfEventLogRecords', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["PDWORD","NumberOfRecords","out"],
      ])

    dll.add_function('GetOldestEventLogRecord', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["PDWORD","OldestRecord","out"],
      ])

    dll.add_function('GetPrivateObjectSecurity', 'BOOL',[
      ["PBLOB","ObjectDescriptor","in"],
      ["PBLOB","SecurityInformation","in"],
      ["PBLOB","ResultantDescriptor","out"],
      ["DWORD","DescriptorLength","in"],
      ["PDWORD","ReturnLength","out"],
      ])

    dll.add_function('GetSecurityDescriptorControl', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["PBLOB","pControl","out"],
      ["PDWORD","lpdwRevision","out"],
      ])

    dll.add_function('GetSecurityDescriptorDacl', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["PBLOB","lpbDaclPresent","out"],
      ["PBLOB","pDacl","out"],
      ["PBLOB","lpbDaclDefaulted","out"],
      ])

    dll.add_function('GetSecurityDescriptorGroup', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["PBLOB","pGroup","out"],
      ["PBLOB","lpbGroupDefaulted","out"],
      ])

    dll.add_function('GetSecurityDescriptorLength', 'DWORD',[
      ["PBLOB","pSecurityDescriptor","in"],
      ])

    dll.add_function('GetSecurityDescriptorOwner', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["PBLOB","pOwner","out"],
      ["PBLOB","lpbOwnerDefaulted","out"],
      ])

    dll.add_function('GetSecurityDescriptorRMControl', 'DWORD',[
      ["PBLOB","SecurityDescriptor","in"],
      ["PBLOB","RMControl","out"],
      ])

    dll.add_function('GetSecurityDescriptorSacl', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["PBLOB","lpbSaclPresent","out"],
      ["PBLOB","pSacl","out"],
      ["PBLOB","lpbSaclDefaulted","out"],
      ])

    dll.add_function('GetSidLengthRequired', 'DWORD',[
      ["BYTE","nSubAuthorityCount","in"],
      ])

    dll.add_function('GetTokenInformation', 'BOOL',[
      ["DWORD","TokenHandle","in"],
      ["DWORD","TokenInformationClass","in"],
      ["PBLOB","TokenInformation","out"],
      ["DWORD","TokenInformationLength","in"],
      ["PDWORD","ReturnLength","out"],
      ])

    dll.add_function('GetUserNameA', 'BOOL',[
      ["PCHAR","lpBuffer","out"],
      ["PDWORD","pcbBuffer","inout"],
      ])

    dll.add_function('GetUserNameW', 'BOOL',[
      ["PWCHAR","lpBuffer","out"],
      ["PDWORD","pcbBuffer","inout"],
      ])

    dll.add_function('GetWindowsAccountDomainSid', 'BOOL',[
      ["LPVOID","pSid","in"],
      ["PBLOB","pDomainSid","out"],
      ["PDWORD","cbDomainSid","inout"],
      ])

    dll.add_function('ImpersonateAnonymousToken', 'BOOL',[
      ["DWORD","ThreadHandle","in"],
      ])

    dll.add_function('ImpersonateLoggedOnUser', 'BOOL',[
      ["DWORD","hToken","in"],
      ])

    dll.add_function('ImpersonateNamedPipeClient', 'BOOL',[
      ["DWORD","hNamedPipe","in"],
      ])

    dll.add_function('ImpersonateSelf', 'BOOL',[
      ["DWORD","ImpersonationLevel","in"],
      ])

    dll.add_function('InitializeAcl', 'BOOL',[
      ["PBLOB","pAcl","out"],
      ["DWORD","nAclLength","in"],
      ["DWORD","dwAclRevision","in"],
      ])

    dll.add_function('InitializeSecurityDescriptor', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","out"],
      ["DWORD","dwRevision","in"],
      ])

    dll.add_function('InitializeSid', 'BOOL',[
      ["PBLOB","Sid","out"],
      ["PBLOB","pIdentifierAuthority","in"],
      ["BYTE","nSubAuthorityCount","in"],
      ])

    dll.add_function('IsTextUnicode', 'BOOL',[
      ["DWORD","iSize","in"],
      ["PDWORD","lpiResult","inout"],
      ])

    dll.add_function('IsTokenRestricted', 'BOOL',[
      ["DWORD","TokenHandle","in"],
      ])

    dll.add_function('IsTokenUntrusted', 'BOOL',[
      ["DWORD","TokenHandle","in"],
      ])

    dll.add_function('IsValidAcl', 'BOOL',[
      ["PBLOB","pAcl","in"],
      ])

    dll.add_function('IsValidSecurityDescriptor', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ])

    dll.add_function('IsValidSid', 'BOOL',[
      ["LPVOID","pSid","in"],
      ])

    dll.add_function('IsWellKnownSid', 'BOOL',[
      ["LPVOID","pSid","in"],
      ["DWORD","WellKnownSidType","in"],
      ])

    dll.add_function('LogonUserA', 'BOOL',[
      ["PCHAR","lpszUsername","in"],
      ["PCHAR","lpszDomain","in"],
      ["PCHAR","lpszPassword","in"],
      ["DWORD","dwLogonType","in"],
      ["DWORD","dwLogonProvider","in"],
      ["PDWORD","phToken","out"],
      ])

    dll.add_function('LogonUserExA', 'BOOL',[
      ["PCHAR","lpszUsername","in"],
      ["PCHAR","lpszDomain","in"],
      ["PCHAR","lpszPassword","in"],
      ["DWORD","dwLogonType","in"],
      ["DWORD","dwLogonProvider","in"],
      ["PDWORD","phToken","out"],
      ["PDWORD","ppLogonSid","out"],
      ["PBLOB","ppProfileBuffer","out"],
      ["PDWORD","pdwProfileLength","out"],
      ["PBLOB","pQuotaLimits","out"],
      ])

    dll.add_function('LogonUserExW', 'BOOL',[
      ["PWCHAR","lpszUsername","in"],
      ["PWCHAR","lpszDomain","in"],
      ["PWCHAR","lpszPassword","in"],
      ["DWORD","dwLogonType","in"],
      ["DWORD","dwLogonProvider","in"],
      ["PDWORD","phToken","out"],
      ["PDWORD","ppLogonSid","out"],
      ["PBLOB","ppProfileBuffer","out"],
      ["PDWORD","pdwProfileLength","out"],
      ["PBLOB","pQuotaLimits","out"],
      ])

    dll.add_function('LogonUserW', 'BOOL',[
      ["PWCHAR","lpszUsername","in"],
      ["PWCHAR","lpszDomain","in"],
      ["PWCHAR","lpszPassword","in"],
      ["DWORD","dwLogonType","in"],
      ["DWORD","dwLogonProvider","in"],
      ["PDWORD","phToken","out"],
      ])

    dll.add_function('LookupAccountNameA', 'BOOL',[
      ["PCHAR","lpSystemName","in"],
      ["PCHAR","lpAccountName","in"],
      ["PBLOB","Sid","out"],
      ["PDWORD","cbSid","inout"],
      ["PCHAR","ReferencedDomainName","out"],
      ["PDWORD","cchReferencedDomainName","inout"],
      ["PBLOB","peUse","out"],
      ])

    dll.add_function('LookupAccountNameW', 'BOOL',[
      ["PWCHAR","lpSystemName","in"],
      ["PWCHAR","lpAccountName","in"],
      ["PBLOB","Sid","out"],
      ["PDWORD","cbSid","inout"],
      ["PWCHAR","ReferencedDomainName","out"],
      ["PDWORD","cchReferencedDomainName","inout"],
      ["PBLOB","peUse","out"],
      ])

    dll.add_function('LookupAccountSidA', 'BOOL',[
      ["PCHAR","lpSystemName","in"],
      ["LPVOID","Sid","in"],
      ["PCHAR","Name","out"],
      ["PDWORD","cchName","inout"],
      ["PCHAR","ReferencedDomainName","out"],
      ["PDWORD","cchReferencedDomainName","inout"],
      ["PBLOB","peUse","out"],
      ])

    dll.add_function('LookupAccountSidW', 'BOOL',[
      ["PWCHAR","lpSystemName","in"],
      ["LPVOID","Sid","in"],
      ["PWCHAR","Name","out"],
      ["PDWORD","cchName","inout"],
      ["PWCHAR","ReferencedDomainName","out"],
      ["PDWORD","cchReferencedDomainName","inout"],
      ["PBLOB","peUse","out"],
      ])

    dll.add_function('LookupPrivilegeDisplayNameA', 'BOOL',[
      ["PCHAR","lpSystemName","in"],
      ["PCHAR","lpName","in"],
      ["PCHAR","lpDisplayName","out"],
      ["PDWORD","cchDisplayName","inout"],
      ["PDWORD","lpLanguageId","out"],
      ])

    dll.add_function('LookupPrivilegeDisplayNameW', 'BOOL',[
      ["PWCHAR","lpSystemName","in"],
      ["PWCHAR","lpName","in"],
      ["PWCHAR","lpDisplayName","out"],
      ["PDWORD","cchDisplayName","inout"],
      ["PDWORD","lpLanguageId","out"],
      ])

    dll.add_function('LookupPrivilegeNameA', 'BOOL',[
      ["PCHAR","lpSystemName","in"],
      ["PBLOB","lpLuid","in"],
      ["PCHAR","lpName","out"],
      ["PDWORD","cchName","inout"],
      ])

    dll.add_function('LookupPrivilegeNameW', 'BOOL',[
      ["PWCHAR","lpSystemName","in"],
      ["PBLOB","lpLuid","in"],
      ["PWCHAR","lpName","out"],
      ["PDWORD","cchName","inout"],
      ])

    dll.add_function('LookupPrivilegeValueA', 'BOOL',[
      ["PCHAR","lpSystemName","in"],
      ["PCHAR","lpName","in"],
      ["PBLOB","lpLuid","out"],
      ])

    dll.add_function('LookupPrivilegeValueW', 'BOOL',[
      ["PWCHAR","lpSystemName","in"],
      ["PWCHAR","lpName","in"],
      ["PBLOB","lpLuid","out"],
      ])

    dll.add_function('MakeAbsoluteSD', 'BOOL',[
      ["PBLOB","pSelfRelativeSecurityDescriptor","in"],
      ["PBLOB","pAbsoluteSecurityDescriptor","out"],
      ["PDWORD","lpdwAbsoluteSecurityDescriptorSize","inout"],
      ["PBLOB","pDacl","out"],
      ["PDWORD","lpdwDaclSize","inout"],
      ["PBLOB","pSacl","out"],
      ["PDWORD","lpdwSaclSize","inout"],
      ["PBLOB","pOwner","out"],
      ["PDWORD","lpdwOwnerSize","inout"],
      ["PBLOB","pPrimaryGroup","out"],
      ["PDWORD","lpdwPrimaryGroupSize","inout"],
      ])

    dll.add_function('MakeAbsoluteSD2', 'BOOL',[
      ["PBLOB","pSelfRelativeSecurityDescriptor","inout"],
      ["PDWORD","lpdwBufferSize","inout"],
      ])

    dll.add_function('MakeSelfRelativeSD', 'BOOL',[
      ["PBLOB","pAbsoluteSecurityDescriptor","in"],
      ["PBLOB","pSelfRelativeSecurityDescriptor","out"],
      ["PDWORD","lpdwBufferLength","inout"],
      ])

    dll.add_function('MapGenericMask', 'VOID',[
      ["PDWORD","AccessMask","inout"],
      ["PBLOB","GenericMapping","in"],
      ])

    dll.add_function('NotifyChangeEventLog', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["DWORD","hEvent","in"],
      ])

    dll.add_function('ObjectCloseAuditAlarmA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["BOOL","GenerateOnClose","in"],
      ])

    dll.add_function('ObjectCloseAuditAlarmW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["BOOL","GenerateOnClose","in"],
      ])

    dll.add_function('ObjectDeleteAuditAlarmA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["BOOL","GenerateOnClose","in"],
      ])

    dll.add_function('ObjectDeleteAuditAlarmW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["BOOL","GenerateOnClose","in"],
      ])

    dll.add_function('ObjectOpenAuditAlarmA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["PCHAR","ObjectTypeName","in"],
      ["PCHAR","ObjectName","in"],
      ["PBLOB","pSecurityDescriptor","in"],
      ["DWORD","ClientToken","in"],
      ["DWORD","DesiredAccess","in"],
      ["DWORD","GrantedAccess","in"],
      ["PBLOB","Privileges","in"],
      ["BOOL","ObjectCreation","in"],
      ["BOOL","AccessGranted","in"],
      ["PBLOB","GenerateOnClose","out"],
      ])

    dll.add_function('ObjectOpenAuditAlarmW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["PWCHAR","ObjectTypeName","in"],
      ["PWCHAR","ObjectName","in"],
      ["PBLOB","pSecurityDescriptor","in"],
      ["DWORD","ClientToken","in"],
      ["DWORD","DesiredAccess","in"],
      ["DWORD","GrantedAccess","in"],
      ["PBLOB","Privileges","in"],
      ["BOOL","ObjectCreation","in"],
      ["BOOL","AccessGranted","in"],
      ["PBLOB","GenerateOnClose","out"],
      ])

    dll.add_function('ObjectPrivilegeAuditAlarmA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["DWORD","ClientToken","in"],
      ["DWORD","DesiredAccess","in"],
      ["PBLOB","Privileges","in"],
      ["BOOL","AccessGranted","in"],
      ])

    dll.add_function('ObjectPrivilegeAuditAlarmW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PBLOB","HandleId","in"],
      ["DWORD","ClientToken","in"],
      ["DWORD","DesiredAccess","in"],
      ["PBLOB","Privileges","in"],
      ["BOOL","AccessGranted","in"],
      ])

    dll.add_function('OpenBackupEventLogA', 'DWORD',[
      ["PCHAR","lpUNCServerName","in"],
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function('OpenBackupEventLogW', 'DWORD',[
      ["PWCHAR","lpUNCServerName","in"],
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function('OpenEncryptedFileRawA', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ["DWORD","ulFlags","in"],
      ["PBLOB","pvContext","out"],
      ])

    dll.add_function('OpenEncryptedFileRawW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ["DWORD","ulFlags","in"],
      ["PBLOB","pvContext","out"],
      ])

    dll.add_function('OpenEventLogA', 'DWORD',[
      ["PCHAR","lpUNCServerName","in"],
      ["PCHAR","lpSourceName","in"],
      ])

    dll.add_function('OpenEventLogW', 'DWORD',[
      ["PWCHAR","lpUNCServerName","in"],
      ["PWCHAR","lpSourceName","in"],
      ])

    dll.add_function('OpenProcessToken', 'BOOL',[
      ["DWORD","ProcessHandle","in"],
      ["DWORD","DesiredAccess","in"],
      ["PDWORD","TokenHandle","out"],
      ])

    dll.add_function('OpenThreadToken', 'BOOL',[
      ["DWORD","ThreadHandle","in"],
      ["DWORD","DesiredAccess","in"],
      ["BOOL","OpenAsSelf","in"],
      ["PDWORD","TokenHandle","out"],
      ])

    dll.add_function('PrivilegeCheck', 'BOOL',[
      ["DWORD","ClientToken","in"],
      ["PBLOB","RequiredPrivileges","inout"],
      ["PBLOB","pfResult","out"],
      ])

    dll.add_function('PrivilegedServiceAuditAlarmA', 'BOOL',[
      ["PCHAR","SubsystemName","in"],
      ["PCHAR","ServiceName","in"],
      ["DWORD","ClientToken","in"],
      ["PBLOB","Privileges","in"],
      ["BOOL","AccessGranted","in"],
      ])

    dll.add_function('PrivilegedServiceAuditAlarmW', 'BOOL',[
      ["PWCHAR","SubsystemName","in"],
      ["PWCHAR","ServiceName","in"],
      ["DWORD","ClientToken","in"],
      ["PBLOB","Privileges","in"],
      ["BOOL","AccessGranted","in"],
      ])

    dll.add_function('ReadEncryptedFileRaw', 'DWORD',[
      ["PBLOB","pfExportCallback","in"],
      ["PBLOB","pvCallbackContext","in"],
      ["PBLOB","pvContext","in"],
      ])

    dll.add_function('ReadEventLogA', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["DWORD","dwReadFlags","in"],
      ["DWORD","dwRecordOffset","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","nNumberOfBytesToRead","in"],
      ["PDWORD","pnBytesRead","out"],
      ["PDWORD","pnMinNumberOfBytesNeeded","out"],
      ])

    dll.add_function('ReadEventLogW', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["DWORD","dwReadFlags","in"],
      ["DWORD","dwRecordOffset","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","nNumberOfBytesToRead","in"],
      ["PDWORD","pnBytesRead","out"],
      ["PDWORD","pnMinNumberOfBytesNeeded","out"],
      ])

    dll.add_function('RegisterEventSourceA', 'DWORD',[
      ["PCHAR","lpUNCServerName","in"],
      ["PCHAR","lpSourceName","in"],
      ])

    dll.add_function('RegisterEventSourceW', 'DWORD',[
      ["PWCHAR","lpUNCServerName","in"],
      ["PWCHAR","lpSourceName","in"],
      ])

    dll.add_function('ReportEventA', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["WORD","wType","in"],
      ["WORD","wCategory","in"],
      ["DWORD","dwEventID","in"],
      ["LPVOID","lpUserSid","in"],
      ["WORD","wNumStrings","in"],
      ["DWORD","dwDataSize","in"],
      ["PBLOB","lpStrings","in"],
      ["PBLOB","lpRawData","in"],
      ])

    dll.add_function('ReportEventW', 'BOOL',[
      ["DWORD","hEventLog","in"],
      ["WORD","wType","in"],
      ["WORD","wCategory","in"],
      ["DWORD","dwEventID","in"],
      ["LPVOID","lpUserSid","in"],
      ["WORD","wNumStrings","in"],
      ["DWORD","dwDataSize","in"],
      ["PBLOB","lpStrings","in"],
      ["PBLOB","lpRawData","in"],
      ])

    dll.add_function('RevertToSelf', 'BOOL',[
      ])

    dll.add_function('SetAclInformation', 'BOOL',[
      ["PBLOB","pAcl","inout"],
      ["PBLOB","pAclInformation","in"],
      ["DWORD","nAclInformationLength","in"],
      ["DWORD","dwAclInformationClass","in"],
      ])

    dll.add_function('SetFileSecurityA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ["PBLOB","SecurityInformation","in"],
      ["PBLOB","pSecurityDescriptor","in"],
      ])

    dll.add_function('SetFileSecurityW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ["PBLOB","SecurityInformation","in"],
      ["PBLOB","pSecurityDescriptor","in"],
      ])

    dll.add_function('SetKernelObjectSecurity', 'BOOL',[
      ["DWORD","Handle","in"],
      ["PBLOB","SecurityInformation","in"],
      ["PBLOB","SecurityDescriptor","in"],
      ])

    dll.add_function('SetPrivateObjectSecurity', 'BOOL',[
      ["PBLOB","SecurityInformation","in"],
      ["PBLOB","ModificationDescriptor","in"],
      ["PBLOB","ObjectsSecurityDescriptor","inout"],
      ["PBLOB","GenericMapping","in"],
      ["DWORD","Token","in"],
      ])

    dll.add_function('SetPrivateObjectSecurityEx', 'BOOL',[
      ["PBLOB","SecurityInformation","in"],
      ["PBLOB","ModificationDescriptor","in"],
      ["PBLOB","ObjectsSecurityDescriptor","inout"],
      ["DWORD","AutoInheritFlags","in"],
      ["PBLOB","GenericMapping","in"],
      ["DWORD","Token","in"],
      ])

    dll.add_function('SetSecurityDescriptorControl', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","in"],
      ["WORD","ControlBitsOfInterest","in"],
      ["WORD","ControlBitsToSet","in"],
      ])

    dll.add_function('SetSecurityDescriptorDacl', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","inout"],
      ["BOOL","bDaclPresent","in"],
      ["PBLOB","pDacl","in"],
      ["BOOL","bDaclDefaulted","in"],
      ])

    dll.add_function('SetSecurityDescriptorGroup', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","inout"],
      ["PBLOB","pGroup","in"],
      ["BOOL","bGroupDefaulted","in"],
      ])

    dll.add_function('SetSecurityDescriptorOwner', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","inout"],
      ["PBLOB","pOwner","in"],
      ["BOOL","bOwnerDefaulted","in"],
      ])

    dll.add_function('SetSecurityDescriptorRMControl', 'DWORD',[
      ["PBLOB","SecurityDescriptor","inout"],
      ["PBLOB","RMControl","in"],
      ])

    dll.add_function('SetSecurityDescriptorSacl', 'BOOL',[
      ["PBLOB","pSecurityDescriptor","inout"],
      ["BOOL","bSaclPresent","in"],
      ["PBLOB","pSacl","in"],
      ["BOOL","bSaclDefaulted","in"],
      ])

    dll.add_function('SetThreadToken', 'BOOL',[
      ["PDWORD","Thread","in"],
      ["DWORD","Token","in"],
      ])

    dll.add_function('SetTokenInformation', 'BOOL',[
      ["DWORD","TokenHandle","in"],
      ["DWORD","TokenInformationClass","in"],
      ["PBLOB","TokenInformation","in"],
      ["DWORD","TokenInformationLength","in"],
      ])

    dll.add_function('WriteEncryptedFileRaw', 'DWORD',[
      ["PBLOB","pfImportCallback","in"],
      ["PBLOB","pvCallbackContext","in"],
      ["PBLOB","pvContext","in"],
      ])

    return dll
  end
end

end; end; end; end; end; end; end


