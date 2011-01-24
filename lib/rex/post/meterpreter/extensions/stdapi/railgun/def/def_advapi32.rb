module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_advapi32

	def self.add_imports(railgun)
		
		railgun.add_dll('advapi32')
		
		# Function to open the Service Control Database
		railgun.add_function( 'advapi32', 'OpenSCManagerA','DWORD',[
			[ "PCHAR", "lpMachineName", "inout" ],
			[ "PCHAR", "lpDatabaseName", "inout" ],
			[ "DWORD", "dwDesiredAccess", "in" ]
			])
			
		# Function for creating a Service
		railgun.add_function( 'advapi32', 'CreateServiceA','DWORD',[
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

		railgun.add_function( 'advapi32', 'OpenServiceA','DWORD',[
			[ "DWORD", "hSCManager", "in" ],
			[ "PCHAR", "lpServiceName", "in" ],
			[ "DWORD", "dwDesiredAccess", "in" ]
			])

		#access rights: SERVICE_CHANGE_CONFIG (0x0002)  SERVICE_START (0x0010)
		#SERVICE_STOP (0x0020)

		railgun.add_function( 'advapi32', 'StartServiceA','BOOL',[
			[ "DWORD", "hService", "in" ],
			[ "DWORD", "dwNumServiceArgs", "in" ],
			[ "PCHAR", "lpServiceArgVectors", "in" ]
			])

		railgun.add_function( 'advapi32', 'ControlService','BOOL',[
			[ "DWORD", "hService", "in" ],
			[ "DWORD", "dwControl", "in" ],
			[ "PBLOB", "lpServiceStatus", "out" ]
			])

		#SERVICE_CONTROL_STOP = 0x00000001

		# _SERVICE_STATUS  is an array of 7 DWORDS -  dwServiceType;
		#dwCurrentState; dwControlsAccepted; dwWin32ExitCode;
		#dwServiceSpecificExitCode; dwCheckPoint; dwWaitHint;

		railgun.add_function( 'advapi32', 'ChangeServiceConfigA','BOOL',[
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

		railgun.add_function( 'advapi32', 'CloseServiceHandle','BOOL',[
			[ "DWORD", "hSCObject", "in" ]
			])
			
		railgun.add_function( 'advapi32', 'AbortSystemShutdownA', 'BOOL',[
			["PCHAR","lpMachineName","in"],
			])

		railgun.add_function( 'advapi32', 'AbortSystemShutdownW', 'BOOL',[
			["PWCHAR","lpMachineName","in"],
			])

		railgun.add_function( 'advapi32', 'InitiateSystemShutdownA', 'BOOL',[
			["PCHAR","lpMachineName","in"],
			["PCHAR","lpMessage","in"],
			["DWORD","dwTimeout","in"],
			["BOOL","bForceAppsClosed","in"],
			["BOOL","bRebootAfterShutdown","in"],
			])

		railgun.add_function( 'advapi32', 'InitiateSystemShutdownExA', 'BOOL',[
			["PCHAR","lpMachineName","in"],
			["PCHAR","lpMessage","in"],
			["DWORD","dwTimeout","in"],
			["BOOL","bForceAppsClosed","in"],
			["BOOL","bRebootAfterShutdown","in"],
			["DWORD","dwReason","in"],
			])

		railgun.add_function( 'advapi32', 'InitiateSystemShutdownExW', 'BOOL',[
			["PWCHAR","lpMachineName","in"],
			["PWCHAR","lpMessage","in"],
			["DWORD","dwTimeout","in"],
			["BOOL","bForceAppsClosed","in"],
			["BOOL","bRebootAfterShutdown","in"],
			["DWORD","dwReason","in"],
			])

		railgun.add_function( 'advapi32', 'InitiateSystemShutdownW', 'BOOL',[
			["PWCHAR","lpMachineName","in"],
			["PWCHAR","lpMessage","in"],
			["DWORD","dwTimeout","in"],
			["BOOL","bForceAppsClosed","in"],
			["BOOL","bRebootAfterShutdown","in"],
			])

		railgun.add_function( 'advapi32', 'RegCloseKey', 'DWORD',[
			["DWORD","hKey","in"],
			])

		railgun.add_function( 'advapi32', 'RegConnectRegistryA', 'DWORD',[
			["PCHAR","lpMachineName","in"],
			["DWORD","hKey","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegConnectRegistryExA', 'DWORD',[
			["PCHAR","lpMachineName","in"],
			["DWORD","hKey","in"],
			["DWORD","Flags","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegConnectRegistryExW', 'DWORD',[
			["PWCHAR","lpMachineName","in"],
			["DWORD","hKey","in"],
			["DWORD","Flags","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegConnectRegistryW', 'DWORD',[
			["PWCHAR","lpMachineName","in"],
			["DWORD","hKey","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegCreateKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegCreateKeyExA', 'DWORD',[
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

		railgun.add_function( 'advapi32', 'RegCreateKeyExW', 'DWORD',[
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

		railgun.add_function( 'advapi32', 'RegCreateKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegDeleteKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			])

		railgun.add_function( 'advapi32', 'RegDeleteKeyExA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			["DWORD","samDesired","in"],
			["DWORD","Reserved","inout"],
			])

		railgun.add_function( 'advapi32', 'RegDeleteKeyExW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			["DWORD","samDesired","in"],
			["DWORD","Reserved","inout"],
			])

		railgun.add_function( 'advapi32', 'RegDeleteKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			])

		railgun.add_function( 'advapi32', 'RegDeleteValueA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpValueName","in"],
			])

		railgun.add_function( 'advapi32', 'RegDeleteValueW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpValueName","in"],
			])

		railgun.add_function( 'advapi32', 'RegDisablePredefinedCache', 'DWORD',[
			])

		railgun.add_function( 'advapi32', 'RegDisableReflectionKey', 'DWORD',[
			["DWORD","hBase","in"],
			])

		railgun.add_function( 'advapi32', 'RegEnableReflectionKey', 'DWORD',[
			["DWORD","hBase","in"],
			])

		railgun.add_function( 'advapi32', 'RegEnumKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["DWORD","dwIndex","in"],
			["PCHAR","lpName","out"],
			["DWORD","cchName","in"],
			])

		railgun.add_function( 'advapi32', 'RegEnumKeyExA', 'DWORD',[
			["DWORD","hKey","in"],
			["DWORD","dwIndex","in"],
			["PCHAR","lpName","out"],
			["PDWORD","lpcchName","inout"],
			["PDWORD","lpReserved","inout"],
			["PCHAR","lpClass","inout"],
			["PDWORD","lpcchClass","inout"],
			["PBLOB","lpftLastWriteTime","out"],
			])

		railgun.add_function( 'advapi32', 'RegEnumKeyExW', 'DWORD',[
			["DWORD","hKey","in"],
			["DWORD","dwIndex","in"],
			["PWCHAR","lpName","out"],
			["PDWORD","lpcchName","inout"],
			["PDWORD","lpReserved","inout"],
			["PWCHAR","lpClass","inout"],
			["PDWORD","lpcchClass","inout"],
			["PBLOB","lpftLastWriteTime","out"],
			])

		railgun.add_function( 'advapi32', 'RegEnumKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["DWORD","dwIndex","in"],
			["PWCHAR","lpName","out"],
			["DWORD","cchName","in"],
			])

		railgun.add_function( 'advapi32', 'RegEnumValueA', 'DWORD',[
			["DWORD","hKey","in"],
			["DWORD","dwIndex","in"],
			["PCHAR","lpValueName","out"],
			["PDWORD","lpcchValueName","inout"],
			["PDWORD","lpReserved","inout"],
			["PDWORD","lpType","out"],
			["PBLOB","lpData","out"],
			["PDWORD","lpcbData","inout"],
			])

		railgun.add_function( 'advapi32', 'RegEnumValueW', 'DWORD',[
			["DWORD","hKey","in"],
			["DWORD","dwIndex","in"],
			["PWCHAR","lpValueName","out"],
			["PDWORD","lpcchValueName","inout"],
			["PDWORD","lpReserved","inout"],
			["PDWORD","lpType","out"],
			["PBLOB","lpData","out"],
			["PDWORD","lpcbData","inout"],
			])

		railgun.add_function( 'advapi32', 'RegFlushKey', 'DWORD',[
			["DWORD","hKey","in"],
			])

		railgun.add_function( 'advapi32', 'RegGetKeySecurity', 'DWORD',[
			["DWORD","hKey","in"],
			["PBLOB","SecurityInformation","in"],
			["PBLOB","pSecurityDescriptor","out"],
			["PDWORD","lpcbSecurityDescriptor","inout"],
			])

		railgun.add_function( 'advapi32', 'RegGetValueA', 'DWORD',[
			["DWORD","hkey","in"],
			["PCHAR","lpSubKey","in"],
			["PCHAR","lpValue","in"],
			["DWORD","dwFlags","in"],
			["PDWORD","pdwType","out"],
			["PBLOB","pvData","out"],
			["PDWORD","pcbData","inout"],
			])

		railgun.add_function( 'advapi32', 'RegGetValueW', 'DWORD',[
			["DWORD","hkey","in"],
			["PWCHAR","lpSubKey","in"],
			["PWCHAR","lpValue","in"],
			["DWORD","dwFlags","in"],
			["PDWORD","pdwType","out"],
			["PBLOB","pvData","out"],
			["PDWORD","pcbData","inout"],
			])

		railgun.add_function( 'advapi32', 'RegLoadKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			["PCHAR","lpFile","in"],
			])

		railgun.add_function( 'advapi32', 'RegLoadKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			["PWCHAR","lpFile","in"],
			])

		railgun.add_function( 'advapi32', 'RegNotifyChangeKeyValue', 'DWORD',[
			["DWORD","hKey","in"],
			["BOOL","bWatchSubtree","in"],
			["DWORD","dwNotifyFilter","in"],
			["DWORD","hEvent","in"],
			["BOOL","fAsynchronous","in"],
			])

		railgun.add_function( 'advapi32', 'RegOpenCurrentUser', 'DWORD',[
			["DWORD","samDesired","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegOpenKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegOpenKeyExA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			["DWORD","ulOptions","inout"],
			["DWORD","samDesired","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegOpenKeyExW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			["DWORD","ulOptions","inout"],
			["DWORD","samDesired","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegOpenKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegOpenUserClassesRoot', 'DWORD',[
			["DWORD","hToken","in"],
			["DWORD","dwOptions","inout"],
			["DWORD","samDesired","in"],
			["PDWORD","phkResult","out"],
			])

		railgun.add_function( 'advapi32', 'RegOverridePredefKey', 'DWORD',[
			["DWORD","hKey","in"],
			["DWORD","hNewHKey","in"],
			])

		railgun.add_function( 'advapi32', 'RegQueryInfoKeyA', 'DWORD',[
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

		railgun.add_function( 'advapi32', 'RegQueryInfoKeyW', 'DWORD',[
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

		railgun.add_function( 'advapi32', 'RegQueryMultipleValuesA', 'DWORD',[
			["DWORD","hKey","in"],
			["PBLOB","val_list","out"],
			["DWORD","num_vals","in"],
			["PCHAR","lpValueBuf","out"],
			["PDWORD","ldwTotsize","inout"],
			])

		railgun.add_function( 'advapi32', 'RegQueryMultipleValuesW', 'DWORD',[
			["DWORD","hKey","in"],
			["PBLOB","val_list","out"],
			["DWORD","num_vals","in"],
			["PWCHAR","lpValueBuf","out"],
			["PDWORD","ldwTotsize","inout"],
			])

		railgun.add_function( 'advapi32', 'RegQueryReflectionKey', 'DWORD',[
			["DWORD","hBase","in"],
			["PBLOB","bIsReflectionDisabled","out"],
			])

		railgun.add_function( 'advapi32', 'RegQueryValueA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			["PCHAR","lpData","out"],
			["PDWORD","lpcbData","inout"],
			])

		railgun.add_function( 'advapi32', 'RegQueryValueExA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpValueName","in"],
			["PDWORD","lpReserved","inout"],
			["PDWORD","lpType","out"],
			["PBLOB","lpData","out"],
			["PDWORD","lpcbData","inout"],
			])

		railgun.add_function( 'advapi32', 'RegQueryValueExW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpValueName","in"],
			["PDWORD","lpReserved","inout"],
			["PDWORD","lpType","out"],
			["PBLOB","lpData","out"],
			["PDWORD","lpcbData","inout"],
			])

		railgun.add_function( 'advapi32', 'RegQueryValueW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			["PWCHAR","lpData","out"],
			["PDWORD","lpcbData","inout"],
			])

		railgun.add_function( 'advapi32', 'RegReplaceKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			["PCHAR","lpNewFile","in"],
			["PCHAR","lpOldFile","in"],
			])

		railgun.add_function( 'advapi32', 'RegReplaceKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			["PWCHAR","lpNewFile","in"],
			["PWCHAR","lpOldFile","in"],
			])

		railgun.add_function( 'advapi32', 'RegRestoreKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpFile","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'advapi32', 'RegRestoreKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpFile","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'advapi32', 'RegSaveKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpFile","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'advapi32', 'RegSaveKeyExA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpFile","in"],
			["PBLOB","lpSecurityAttributes","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'advapi32', 'RegSaveKeyExW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpFile","in"],
			["PBLOB","lpSecurityAttributes","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'advapi32', 'RegSaveKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpFile","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'advapi32', 'RegSetKeySecurity', 'DWORD',[
			["DWORD","hKey","in"],
			["PBLOB","SecurityInformation","in"],
			["PBLOB","pSecurityDescriptor","in"],
			])

		railgun.add_function( 'advapi32', 'RegSetValueA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			["DWORD","dwType","in"],
			["PCHAR","lpData","in"],
			["DWORD","cbData","in"],
			])

		railgun.add_function( 'advapi32', 'RegSetValueExA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpValueName","in"],
			["DWORD","Reserved","inout"],
			["DWORD","dwType","in"],
			["PBLOB","lpData","in"],
			["DWORD","cbData","in"],
			])

		railgun.add_function( 'advapi32', 'RegSetValueExW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpValueName","in"],
			["DWORD","Reserved","inout"],
			["DWORD","dwType","in"],
			["PBLOB","lpData","in"],
			["DWORD","cbData","in"],
			])

		railgun.add_function( 'advapi32', 'RegSetValueW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			["DWORD","dwType","in"],
			["PWCHAR","lpData","in"],
			["DWORD","cbData","in"],
			])

		railgun.add_function( 'advapi32', 'RegUnLoadKeyA', 'DWORD',[
			["DWORD","hKey","in"],
			["PCHAR","lpSubKey","in"],
			])

		railgun.add_function( 'advapi32', 'RegUnLoadKeyW', 'DWORD',[
			["DWORD","hKey","in"],
			["PWCHAR","lpSubKey","in"],
			])

		railgun.add_function( 'advapi32', 'Wow64Win32ApiEntry', 'DWORD',[
			["DWORD","dwFuncNumber","in"],
			["DWORD","dwFlag","in"],
			["DWORD","dwRes","in"],
			])

		railgun.add_function( 'advapi32', 'AccessCheck', 'BOOL',[
			["PBLOB","pSecurityDescriptor","in"],
			["DWORD","ClientToken","in"],
			["DWORD","DesiredAccess","in"],
			["PBLOB","GenericMapping","in"],
			["PBLOB","PrivilegeSet","out"],
			["PDWORD","PrivilegeSetLength","inout"],
			["PDWORD","GrantedAccess","out"],
			["PBLOB","AccessStatus","out"],
			])

		railgun.add_function( 'advapi32', 'AccessCheckAndAuditAlarmA', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckAndAuditAlarmW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckByType', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckByTypeAndAuditAlarmA', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckByTypeAndAuditAlarmW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckByTypeResultList', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckByTypeResultListAndAuditAlarmA', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckByTypeResultListAndAuditAlarmByHandleA', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckByTypeResultListAndAuditAlarmByHandleW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AccessCheckByTypeResultListAndAuditAlarmW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AddAccessAllowedAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AccessMask","in"],
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessAllowedAceEx', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","AccessMask","in"],
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessAllowedObjectAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","AccessMask","in"],
			["PBLOB","ObjectTypeGuid","in"],
			["PBLOB","InheritedObjectTypeGuid","in"],
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessDeniedAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AccessMask","in"],
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessDeniedAceEx', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","AccessMask","in"],
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessDeniedObjectAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","AccessMask","in"],
			["PBLOB","ObjectTypeGuid","in"],
			["PBLOB","InheritedObjectTypeGuid","in"],
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","dwStartingAceIndex","in"],
			["PBLOB","pAceList","in"],
			["DWORD","nAceListLength","in"],
			])

		railgun.add_function( 'advapi32', 'AddAuditAccessAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","dwAccessMask","in"],
			["LPVOID","pSid","in"],
			["BOOL","bAuditSuccess","in"],
			["BOOL","bAuditFailure","in"],
			])

		railgun.add_function( 'advapi32', 'AddAuditAccessAceEx', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","dwAccessMask","in"],
			["LPVOID","pSid","in"],
			["BOOL","bAuditSuccess","in"],
			["BOOL","bAuditFailure","in"],
			])

		railgun.add_function( 'advapi32', 'AddAuditAccessObjectAce', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AdjustTokenGroups', 'BOOL',[
			["DWORD","TokenHandle","in"],
			["BOOL","ResetToDefault","in"],
			["PBLOB","NewState","in"],
			["DWORD","BufferLength","in"],
			["PBLOB","PreviousState","out"],
			["PDWORD","ReturnLength","out"],
			])

		railgun.add_function( 'advapi32', 'AdjustTokenPrivileges', 'BOOL',[
			["DWORD","TokenHandle","in"],
			["BOOL","DisableAllPrivileges","in"],
			["PBLOB","NewState","in"],
			["DWORD","BufferLength","in"],
			["PBLOB","PreviousState","out"],
			["PDWORD","ReturnLength","out"],
			])

		railgun.add_function( 'advapi32', 'AllocateAndInitializeSid', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'AllocateLocallyUniqueId', 'BOOL',[
			["PBLOB","Luid","out"],
			])

		railgun.add_function( 'advapi32', 'AreAllAccessesGranted', 'BOOL',[
			["DWORD","GrantedAccess","in"],
			["DWORD","DesiredAccess","in"],
			])

		railgun.add_function( 'advapi32', 'AreAnyAccessesGranted', 'BOOL',[
			["DWORD","GrantedAccess","in"],
			["DWORD","DesiredAccess","in"],
			])

		railgun.add_function( 'advapi32', 'BackupEventLogA', 'BOOL',[
			["DWORD","hEventLog","in"],
			["PCHAR","lpBackupFileName","in"],
			])

		railgun.add_function( 'advapi32', 'BackupEventLogW', 'BOOL',[
			["DWORD","hEventLog","in"],
			["PWCHAR","lpBackupFileName","in"],
			])

		railgun.add_function( 'advapi32', 'CheckTokenMembership', 'BOOL',[
			["DWORD","TokenHandle","in"],
			["PBLOB","SidToCheck","in"],
			["PBLOB","IsMember","out"],
			])

		railgun.add_function( 'advapi32', 'ClearEventLogA', 'BOOL',[
			["DWORD","hEventLog","in"],
			["PCHAR","lpBackupFileName","in"],
			])

		railgun.add_function( 'advapi32', 'ClearEventLogW', 'BOOL',[
			["DWORD","hEventLog","in"],
			["PWCHAR","lpBackupFileName","in"],
			])

		railgun.add_function( 'advapi32', 'CloseEncryptedFileRaw', 'VOID',[
			["PBLOB","pvContext","in"],
			])

		railgun.add_function( 'advapi32', 'CloseEventLog', 'BOOL',[
			["DWORD","hEventLog","in"],
			])

		railgun.add_function( 'advapi32', 'ConvertToAutoInheritPrivateObjectSecurity', 'BOOL',[
			["PBLOB","ParentDescriptor","in"],
			["PBLOB","CurrentSecurityDescriptor","in"],
			["PBLOB","NewSecurityDescriptor","out"],
			["PBLOB","ObjectType","in"],
			["BOOL","IsDirectoryObject","in"],
			["PBLOB","GenericMapping","in"],
			])

		railgun.add_function( 'advapi32', 'ConvertStringSidToSidA', 'BOOL',[
			["PCHAR","StringSid","in"],
			["PDWORD","pSid","out"],
			])

		railgun.add_function( 'advapi32', 'ConvertStringSidToSidW', 'BOOL',[
			["PWCHAR","StringSid","in"],
			["PDWORD","pSid","out"],
			])

		railgun.add_function( 'advapi32', 'CopySid', 'BOOL',[
			["DWORD","nDestinationSidLength","in"],
			["PBLOB","pDestinationSid","out"],
			["LPVOID","pSourceSid","in"],
			])

		railgun.add_function( 'advapi32', 'CreatePrivateObjectSecurity', 'BOOL',[
			["PBLOB","ParentDescriptor","in"],
			["PBLOB","CreatorDescriptor","in"],
			["PBLOB","NewDescriptor","out"],
			["BOOL","IsDirectoryObject","in"],
			["DWORD","Token","in"],
			["PBLOB","GenericMapping","in"],
			])

		railgun.add_function( 'advapi32', 'CreatePrivateObjectSecurityEx', 'BOOL',[
			["PBLOB","ParentDescriptor","in"],
			["PBLOB","CreatorDescriptor","in"],
			["PBLOB","NewDescriptor","out"],
			["PBLOB","ObjectType","in"],
			["BOOL","IsContainerObject","in"],
			["DWORD","AutoInheritFlags","in"],
			["DWORD","Token","in"],
			["PBLOB","GenericMapping","in"],
			])

		railgun.add_function( 'advapi32', 'CreatePrivateObjectSecurityWithMultipleInheritance', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'CreateProcessAsUserA', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'CreateProcessAsUserW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'CreateProcessWithLogonW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'CreateProcessWithTokenW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'CreateRestrictedToken', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'CreateWellKnownSid', 'BOOL',[
			["DWORD","WellKnownSidType","in"],
			["PBLOB","DomainSid","in"],
			["PBLOB","pSid","out"],
			["PDWORD","cbSid","inout"],
			])

		railgun.add_function( 'advapi32', 'DecryptFileA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["DWORD","dwReserved","inout"],
			])

		railgun.add_function( 'advapi32', 'DecryptFileW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["DWORD","dwReserved","inout"],
			])

		railgun.add_function( 'advapi32', 'DeleteAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceIndex","in"],
			])

		railgun.add_function( 'advapi32', 'DeregisterEventSource', 'BOOL',[
			["DWORD","hEventLog","in"],
			])

		railgun.add_function( 'advapi32', 'DestroyPrivateObjectSecurity', 'BOOL',[
			["PBLOB","ObjectDescriptor","in"],
			])

		railgun.add_function( 'advapi32', 'DuplicateToken', 'BOOL',[
			["DWORD","ExistingTokenHandle","in"],
			["DWORD","ImpersonationLevel","in"],
			["PDWORD","DuplicateTokenHandle","out"],
			])

		railgun.add_function( 'advapi32', 'DuplicateTokenEx', 'BOOL',[
			["DWORD","hExistingToken","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpTokenAttributes","in"],
			["DWORD","ImpersonationLevel","in"],
			["DWORD","TokenType","in"],
			["PDWORD","phNewToken","out"],
			])

		railgun.add_function( 'advapi32', 'EncryptFileA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'advapi32', 'EncryptFileW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'advapi32', 'EqualDomainSid', 'BOOL',[
			["LPVOID","pSid1","in"],
			["LPVOID","pSid2","in"],
			["PBLOB","pfEqual","out"],
			])

		railgun.add_function( 'advapi32', 'EqualPrefixSid', 'BOOL',[
			["LPVOID","pSid1","in"],
			["LPVOID","pSid2","in"],
			])

		railgun.add_function( 'advapi32', 'EqualSid', 'BOOL',[
			["LPVOID","pSid1","in"],
			["LPVOID","pSid2","in"],
			])

		railgun.add_function( 'advapi32', 'FileEncryptionStatusA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["PDWORD","lpStatus","out"],
			])

		railgun.add_function( 'advapi32', 'FileEncryptionStatusW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["PDWORD","lpStatus","out"],
			])

		railgun.add_function( 'advapi32', 'FindFirstFreeAce', 'BOOL',[
			["PBLOB","pAcl","in"],
			["PBLOB","pAce","out"],
			])

		railgun.add_function( 'advapi32', 'FreeSid', 'LPVOID',[
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'GetAce', 'BOOL',[
			["PBLOB","pAcl","in"],
			["DWORD","dwAceIndex","in"],
			["PBLOB","pAce","out"],
			])

		railgun.add_function( 'advapi32', 'GetAclInformation', 'BOOL',[
			["PBLOB","pAcl","in"],
			["PBLOB","pAclInformation","out"],
			["DWORD","nAclInformationLength","in"],
			["DWORD","dwAclInformationClass","in"],
			])

		railgun.add_function( 'advapi32', 'GetCurrentHwProfileA', 'BOOL',[
			["PBLOB","lpHwProfileInfo","out"],
			])

		railgun.add_function( 'advapi32', 'GetCurrentHwProfileW', 'BOOL',[
			["PBLOB","lpHwProfileInfo","out"],
			])

		railgun.add_function( 'advapi32', 'GetEventLogInformation', 'BOOL',[
			["DWORD","hEventLog","in"],
			["DWORD","dwInfoLevel","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","cbBufSize","in"],
			["PDWORD","pcbBytesNeeded","out"],
			])

		railgun.add_function( 'advapi32', 'GetFileSecurityA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["PBLOB","RequestedInformation","in"],
			["PBLOB","pSecurityDescriptor","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'advapi32', 'GetFileSecurityW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","RequestedInformation","in"],
			["PBLOB","pSecurityDescriptor","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'advapi32', 'GetKernelObjectSecurity', 'BOOL',[
			["DWORD","Handle","in"],
			["PBLOB","RequestedInformation","in"],
			["PBLOB","pSecurityDescriptor","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'advapi32', 'GetLengthSid', 'DWORD',[
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'GetNumberOfEventLogRecords', 'BOOL',[
			["DWORD","hEventLog","in"],
			["PDWORD","NumberOfRecords","out"],
			])

		railgun.add_function( 'advapi32', 'GetOldestEventLogRecord', 'BOOL',[
			["DWORD","hEventLog","in"],
			["PDWORD","OldestRecord","out"],
			])

		railgun.add_function( 'advapi32', 'GetPrivateObjectSecurity', 'BOOL',[
			["PBLOB","ObjectDescriptor","in"],
			["PBLOB","SecurityInformation","in"],
			["PBLOB","ResultantDescriptor","out"],
			["DWORD","DescriptorLength","in"],
			["PDWORD","ReturnLength","out"],
			])

		railgun.add_function( 'advapi32', 'GetSecurityDescriptorControl', 'BOOL',[
			["PBLOB","pSecurityDescriptor","in"],
			["PBLOB","pControl","out"],
			["PDWORD","lpdwRevision","out"],
			])

		railgun.add_function( 'advapi32', 'GetSecurityDescriptorDacl', 'BOOL',[
			["PBLOB","pSecurityDescriptor","in"],
			["PBLOB","lpbDaclPresent","out"],
			["PBLOB","pDacl","out"],
			["PBLOB","lpbDaclDefaulted","out"],
			])

		railgun.add_function( 'advapi32', 'GetSecurityDescriptorGroup', 'BOOL',[
			["PBLOB","pSecurityDescriptor","in"],
			["PBLOB","pGroup","out"],
			["PBLOB","lpbGroupDefaulted","out"],
			])

		railgun.add_function( 'advapi32', 'GetSecurityDescriptorLength', 'DWORD',[
			["PBLOB","pSecurityDescriptor","in"],
			])

		railgun.add_function( 'advapi32', 'GetSecurityDescriptorOwner', 'BOOL',[
			["PBLOB","pSecurityDescriptor","in"],
			["PBLOB","pOwner","out"],
			["PBLOB","lpbOwnerDefaulted","out"],
			])

		railgun.add_function( 'advapi32', 'GetSecurityDescriptorRMControl', 'DWORD',[
			["PBLOB","SecurityDescriptor","in"],
			["PBLOB","RMControl","out"],
			])

		railgun.add_function( 'advapi32', 'GetSecurityDescriptorSacl', 'BOOL',[
			["PBLOB","pSecurityDescriptor","in"],
			["PBLOB","lpbSaclPresent","out"],
			["PBLOB","pSacl","out"],
			["PBLOB","lpbSaclDefaulted","out"],
			])

		railgun.add_function( 'advapi32', 'GetSidLengthRequired', 'DWORD',[
			["BYTE","nSubAuthorityCount","in"],
			])

		railgun.add_function( 'advapi32', 'GetTokenInformation', 'BOOL',[
			["DWORD","TokenHandle","in"],
			["DWORD","TokenInformationClass","in"],
			["PBLOB","TokenInformation","out"],
			["DWORD","TokenInformationLength","in"],
			["PDWORD","ReturnLength","out"],
			])

		railgun.add_function( 'advapi32', 'GetUserNameA', 'BOOL',[
			["PCHAR","lpBuffer","out"],
			["PDWORD","pcbBuffer","inout"],
			])

		railgun.add_function( 'advapi32', 'GetUserNameW', 'BOOL',[
			["PWCHAR","lpBuffer","out"],
			["PDWORD","pcbBuffer","inout"],
			])

		railgun.add_function( 'advapi32', 'GetWindowsAccountDomainSid', 'BOOL',[
			["LPVOID","pSid","in"],
			["PBLOB","pDomainSid","out"],
			["PDWORD","cbDomainSid","inout"],
			])

		railgun.add_function( 'advapi32', 'ImpersonateAnonymousToken', 'BOOL',[
			["DWORD","ThreadHandle","in"],
			])

		railgun.add_function( 'advapi32', 'ImpersonateLoggedOnUser', 'BOOL',[
			["DWORD","hToken","in"],
			])

		railgun.add_function( 'advapi32', 'ImpersonateNamedPipeClient', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			])

		railgun.add_function( 'advapi32', 'ImpersonateSelf', 'BOOL',[
			["DWORD","ImpersonationLevel","in"],
			])

		railgun.add_function( 'advapi32', 'InitializeAcl', 'BOOL',[
			["PBLOB","pAcl","out"],
			["DWORD","nAclLength","in"],
			["DWORD","dwAclRevision","in"],
			])

		railgun.add_function( 'advapi32', 'InitializeSecurityDescriptor', 'BOOL',[
			["PBLOB","pSecurityDescriptor","out"],
			["DWORD","dwRevision","in"],
			])

		railgun.add_function( 'advapi32', 'InitializeSid', 'BOOL',[
			["PBLOB","Sid","out"],
			["PBLOB","pIdentifierAuthority","in"],
			["BYTE","nSubAuthorityCount","in"],
			])

		railgun.add_function( 'advapi32', 'IsTextUnicode', 'BOOL',[
			["DWORD","iSize","in"],
			["PDWORD","lpiResult","inout"],
			])

		railgun.add_function( 'advapi32', 'IsTokenRestricted', 'BOOL',[
			["DWORD","TokenHandle","in"],
			])

		railgun.add_function( 'advapi32', 'IsTokenUntrusted', 'BOOL',[
			["DWORD","TokenHandle","in"],
			])

		railgun.add_function( 'advapi32', 'IsValidAcl', 'BOOL',[
			["PBLOB","pAcl","in"],
			])

		railgun.add_function( 'advapi32', 'IsValidSecurityDescriptor', 'BOOL',[
			["PBLOB","pSecurityDescriptor","in"],
			])

		railgun.add_function( 'advapi32', 'IsValidSid', 'BOOL',[
			["LPVOID","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'IsWellKnownSid', 'BOOL',[
			["LPVOID","pSid","in"],
			["DWORD","WellKnownSidType","in"],
			])

		railgun.add_function( 'advapi32', 'LogonUserA', 'BOOL',[
			["PCHAR","lpszUsername","in"],
			["PCHAR","lpszDomain","in"],
			["PCHAR","lpszPassword","in"],
			["DWORD","dwLogonType","in"],
			["DWORD","dwLogonProvider","in"],
			["PDWORD","phToken","out"],
			])

		railgun.add_function( 'advapi32', 'LogonUserExA', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'LogonUserExW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'LogonUserW', 'BOOL',[
			["PWCHAR","lpszUsername","in"],
			["PWCHAR","lpszDomain","in"],
			["PWCHAR","lpszPassword","in"],
			["DWORD","dwLogonType","in"],
			["DWORD","dwLogonProvider","in"],
			["PDWORD","phToken","out"],
			])

		railgun.add_function( 'advapi32', 'LookupAccountNameA', 'BOOL',[
			["PCHAR","lpSystemName","in"],
			["PCHAR","lpAccountName","in"],
			["PBLOB","Sid","out"],
			["PDWORD","cbSid","inout"],
			["PCHAR","ReferencedDomainName","out"],
			["PDWORD","cchReferencedDomainName","inout"],
			["PBLOB","peUse","out"],
			])

		railgun.add_function( 'advapi32', 'LookupAccountNameW', 'BOOL',[
			["PWCHAR","lpSystemName","in"],
			["PWCHAR","lpAccountName","in"],
			["PBLOB","Sid","out"],
			["PDWORD","cbSid","inout"],
			["PWCHAR","ReferencedDomainName","out"],
			["PDWORD","cchReferencedDomainName","inout"],
			["PBLOB","peUse","out"],
			])

		railgun.add_function( 'advapi32', 'LookupAccountSidA', 'BOOL',[
			["PCHAR","lpSystemName","in"],
			["LPVOID","Sid","in"],
			["PCHAR","Name","out"],
			["PDWORD","cchName","inout"],
			["PCHAR","ReferencedDomainName","out"],
			["PDWORD","cchReferencedDomainName","inout"],
			["PBLOB","peUse","out"],
			])

		railgun.add_function( 'advapi32', 'LookupAccountSidW', 'BOOL',[
			["PWCHAR","lpSystemName","in"],
			["LPVOID","Sid","in"],
			["PWCHAR","Name","out"],
			["PDWORD","cchName","inout"],
			["PWCHAR","ReferencedDomainName","out"],
			["PDWORD","cchReferencedDomainName","inout"],
			["PBLOB","peUse","out"],
			])

		railgun.add_function( 'advapi32', 'LookupPrivilegeDisplayNameA', 'BOOL',[
			["PCHAR","lpSystemName","in"],
			["PCHAR","lpName","in"],
			["PCHAR","lpDisplayName","out"],
			["PDWORD","cchDisplayName","inout"],
			["PDWORD","lpLanguageId","out"],
			])

		railgun.add_function( 'advapi32', 'LookupPrivilegeDisplayNameW', 'BOOL',[
			["PWCHAR","lpSystemName","in"],
			["PWCHAR","lpName","in"],
			["PWCHAR","lpDisplayName","out"],
			["PDWORD","cchDisplayName","inout"],
			["PDWORD","lpLanguageId","out"],
			])

		railgun.add_function( 'advapi32', 'LookupPrivilegeNameA', 'BOOL',[
			["PCHAR","lpSystemName","in"],
			["PBLOB","lpLuid","in"],
			["PCHAR","lpName","out"],
			["PDWORD","cchName","inout"],
			])

		railgun.add_function( 'advapi32', 'LookupPrivilegeNameW', 'BOOL',[
			["PWCHAR","lpSystemName","in"],
			["PBLOB","lpLuid","in"],
			["PWCHAR","lpName","out"],
			["PDWORD","cchName","inout"],
			])

		railgun.add_function( 'advapi32', 'LookupPrivilegeValueA', 'BOOL',[
			["PCHAR","lpSystemName","in"],
			["PCHAR","lpName","in"],
			["PBLOB","lpLuid","out"],
			])

		railgun.add_function( 'advapi32', 'LookupPrivilegeValueW', 'BOOL',[
			["PWCHAR","lpSystemName","in"],
			["PWCHAR","lpName","in"],
			["PBLOB","lpLuid","out"],
			])

		railgun.add_function( 'advapi32', 'MakeAbsoluteSD', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'MakeAbsoluteSD2', 'BOOL',[
			["PBLOB","pSelfRelativeSecurityDescriptor","inout"],
			["PDWORD","lpdwBufferSize","inout"],
			])

		railgun.add_function( 'advapi32', 'MakeSelfRelativeSD', 'BOOL',[
			["PBLOB","pAbsoluteSecurityDescriptor","in"],
			["PBLOB","pSelfRelativeSecurityDescriptor","out"],
			["PDWORD","lpdwBufferLength","inout"],
			])

		railgun.add_function( 'advapi32', 'MapGenericMask', 'VOID',[
			["PDWORD","AccessMask","inout"],
			["PBLOB","GenericMapping","in"],
			])

		railgun.add_function( 'advapi32', 'NotifyChangeEventLog', 'BOOL',[
			["DWORD","hEventLog","in"],
			["DWORD","hEvent","in"],
			])

		railgun.add_function( 'advapi32', 'ObjectCloseAuditAlarmA', 'BOOL',[
			["PCHAR","SubsystemName","in"],
			["PBLOB","HandleId","in"],
			["BOOL","GenerateOnClose","in"],
			])

		railgun.add_function( 'advapi32', 'ObjectCloseAuditAlarmW', 'BOOL',[
			["PWCHAR","SubsystemName","in"],
			["PBLOB","HandleId","in"],
			["BOOL","GenerateOnClose","in"],
			])

		railgun.add_function( 'advapi32', 'ObjectDeleteAuditAlarmA', 'BOOL',[
			["PCHAR","SubsystemName","in"],
			["PBLOB","HandleId","in"],
			["BOOL","GenerateOnClose","in"],
			])

		railgun.add_function( 'advapi32', 'ObjectDeleteAuditAlarmW', 'BOOL',[
			["PWCHAR","SubsystemName","in"],
			["PBLOB","HandleId","in"],
			["BOOL","GenerateOnClose","in"],
			])

		railgun.add_function( 'advapi32', 'ObjectOpenAuditAlarmA', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'ObjectOpenAuditAlarmW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'ObjectPrivilegeAuditAlarmA', 'BOOL',[
			["PCHAR","SubsystemName","in"],
			["PBLOB","HandleId","in"],
			["DWORD","ClientToken","in"],
			["DWORD","DesiredAccess","in"],
			["PBLOB","Privileges","in"],
			["BOOL","AccessGranted","in"],
			])

		railgun.add_function( 'advapi32', 'ObjectPrivilegeAuditAlarmW', 'BOOL',[
			["PWCHAR","SubsystemName","in"],
			["PBLOB","HandleId","in"],
			["DWORD","ClientToken","in"],
			["DWORD","DesiredAccess","in"],
			["PBLOB","Privileges","in"],
			["BOOL","AccessGranted","in"],
			])

		railgun.add_function( 'advapi32', 'OpenBackupEventLogA', 'DWORD',[
			["PCHAR","lpUNCServerName","in"],
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'advapi32', 'OpenBackupEventLogW', 'DWORD',[
			["PWCHAR","lpUNCServerName","in"],
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'advapi32', 'OpenEncryptedFileRawA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["DWORD","ulFlags","in"],
			["PBLOB","pvContext","out"],
			])

		railgun.add_function( 'advapi32', 'OpenEncryptedFileRawW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["DWORD","ulFlags","in"],
			["PBLOB","pvContext","out"],
			])

		railgun.add_function( 'advapi32', 'OpenEventLogA', 'DWORD',[
			["PCHAR","lpUNCServerName","in"],
			["PCHAR","lpSourceName","in"],
			])

		railgun.add_function( 'advapi32', 'OpenEventLogW', 'DWORD',[
			["PWCHAR","lpUNCServerName","in"],
			["PWCHAR","lpSourceName","in"],
			])

		railgun.add_function( 'advapi32', 'OpenProcessToken', 'BOOL',[
			["DWORD","ProcessHandle","in"],
			["DWORD","DesiredAccess","in"],
			["PDWORD","TokenHandle","out"],
			])

		railgun.add_function( 'advapi32', 'OpenThreadToken', 'BOOL',[
			["DWORD","ThreadHandle","in"],
			["DWORD","DesiredAccess","in"],
			["BOOL","OpenAsSelf","in"],
			["PDWORD","TokenHandle","out"],
			])

		railgun.add_function( 'advapi32', 'PrivilegeCheck', 'BOOL',[
			["DWORD","ClientToken","in"],
			["PBLOB","RequiredPrivileges","inout"],
			["PBLOB","pfResult","out"],
			])

		railgun.add_function( 'advapi32', 'PrivilegedServiceAuditAlarmA', 'BOOL',[
			["PCHAR","SubsystemName","in"],
			["PCHAR","ServiceName","in"],
			["DWORD","ClientToken","in"],
			["PBLOB","Privileges","in"],
			["BOOL","AccessGranted","in"],
			])

		railgun.add_function( 'advapi32', 'PrivilegedServiceAuditAlarmW', 'BOOL',[
			["PWCHAR","SubsystemName","in"],
			["PWCHAR","ServiceName","in"],
			["DWORD","ClientToken","in"],
			["PBLOB","Privileges","in"],
			["BOOL","AccessGranted","in"],
			])

		railgun.add_function( 'advapi32', 'ReadEncryptedFileRaw', 'DWORD',[
			["PBLOB","pfExportCallback","in"],
			["PBLOB","pvCallbackContext","in"],
			["PBLOB","pvContext","in"],
			])

		railgun.add_function( 'advapi32', 'ReadEventLogA', 'BOOL',[
			["DWORD","hEventLog","in"],
			["DWORD","dwReadFlags","in"],
			["DWORD","dwRecordOffset","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PDWORD","pnBytesRead","out"],
			["PDWORD","pnMinNumberOfBytesNeeded","out"],
			])

		railgun.add_function( 'advapi32', 'ReadEventLogW', 'BOOL',[
			["DWORD","hEventLog","in"],
			["DWORD","dwReadFlags","in"],
			["DWORD","dwRecordOffset","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PDWORD","pnBytesRead","out"],
			["PDWORD","pnMinNumberOfBytesNeeded","out"],
			])

		railgun.add_function( 'advapi32', 'RegisterEventSourceA', 'DWORD',[
			["PCHAR","lpUNCServerName","in"],
			["PCHAR","lpSourceName","in"],
			])

		railgun.add_function( 'advapi32', 'RegisterEventSourceW', 'DWORD',[
			["PWCHAR","lpUNCServerName","in"],
			["PWCHAR","lpSourceName","in"],
			])

		railgun.add_function( 'advapi32', 'ReportEventA', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'ReportEventW', 'BOOL',[
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

		railgun.add_function( 'advapi32', 'RevertToSelf', 'BOOL',[
			])

		railgun.add_function( 'advapi32', 'SetAclInformation', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["PBLOB","pAclInformation","in"],
			["DWORD","nAclInformationLength","in"],
			["DWORD","dwAclInformationClass","in"],
			])

		railgun.add_function( 'advapi32', 'SetFileSecurityA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["PBLOB","SecurityInformation","in"],
			["PBLOB","pSecurityDescriptor","in"],
			])

		railgun.add_function( 'advapi32', 'SetFileSecurityW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","SecurityInformation","in"],
			["PBLOB","pSecurityDescriptor","in"],
			])

		railgun.add_function( 'advapi32', 'SetKernelObjectSecurity', 'BOOL',[
			["DWORD","Handle","in"],
			["PBLOB","SecurityInformation","in"],
			["PBLOB","SecurityDescriptor","in"],
			])

		railgun.add_function( 'advapi32', 'SetPrivateObjectSecurity', 'BOOL',[
			["PBLOB","SecurityInformation","in"],
			["PBLOB","ModificationDescriptor","in"],
			["PBLOB","ObjectsSecurityDescriptor","inout"],
			["PBLOB","GenericMapping","in"],
			["DWORD","Token","in"],
			])

		railgun.add_function( 'advapi32', 'SetPrivateObjectSecurityEx', 'BOOL',[
			["PBLOB","SecurityInformation","in"],
			["PBLOB","ModificationDescriptor","in"],
			["PBLOB","ObjectsSecurityDescriptor","inout"],
			["DWORD","AutoInheritFlags","in"],
			["PBLOB","GenericMapping","in"],
			["DWORD","Token","in"],
			])

		railgun.add_function( 'advapi32', 'SetSecurityDescriptorControl', 'BOOL',[
			["PBLOB","pSecurityDescriptor","in"],
			["WORD","ControlBitsOfInterest","in"],
			["WORD","ControlBitsToSet","in"],
			])

		railgun.add_function( 'advapi32', 'SetSecurityDescriptorDacl', 'BOOL',[
			["PBLOB","pSecurityDescriptor","inout"],
			["BOOL","bDaclPresent","in"],
			["PBLOB","pDacl","in"],
			["BOOL","bDaclDefaulted","in"],
			])

		railgun.add_function( 'advapi32', 'SetSecurityDescriptorGroup', 'BOOL',[
			["PBLOB","pSecurityDescriptor","inout"],
			["PBLOB","pGroup","in"],
			["BOOL","bGroupDefaulted","in"],
			])

		railgun.add_function( 'advapi32', 'SetSecurityDescriptorOwner', 'BOOL',[
			["PBLOB","pSecurityDescriptor","inout"],
			["PBLOB","pOwner","in"],
			["BOOL","bOwnerDefaulted","in"],
			])

		railgun.add_function( 'advapi32', 'SetSecurityDescriptorRMControl', 'DWORD',[
			["PBLOB","SecurityDescriptor","inout"],
			["PBLOB","RMControl","in"],
			])

		railgun.add_function( 'advapi32', 'SetSecurityDescriptorSacl', 'BOOL',[
			["PBLOB","pSecurityDescriptor","inout"],
			["BOOL","bSaclPresent","in"],
			["PBLOB","pSacl","in"],
			["BOOL","bSaclDefaulted","in"],
			])

		railgun.add_function( 'advapi32', 'SetThreadToken', 'BOOL',[
			["PDWORD","Thread","in"],
			["DWORD","Token","in"],
			])

		railgun.add_function( 'advapi32', 'SetTokenInformation', 'BOOL',[
			["DWORD","TokenHandle","in"],
			["DWORD","TokenInformationClass","in"],
			["PBLOB","TokenInformation","in"],
			["DWORD","TokenInformationLength","in"],
			])

		railgun.add_function( 'advapi32', 'WriteEncryptedFileRaw', 'DWORD',[
			["PBLOB","pfImportCallback","in"],
			["PBLOB","pvCallbackContext","in"],
			["PBLOB","pvContext","in"],
			])

	end
	
end

end; end; end; end; end; end; end


