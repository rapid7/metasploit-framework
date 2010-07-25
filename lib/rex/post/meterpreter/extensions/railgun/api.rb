
module Rex
module Post
module Meterpreter
module Extensions
module Railgun
class ApiDefinitions
	def self.add_imports(railgun)

		railgun.add_dll('iphlpapi','iphlpapi')
		railgun.add_function( 'iphlpapi', 'CancelIPChangeNotify', 'BOOL',[
			["PBLOB","notifyOverlapped","in"],
			])

		railgun.add_function( 'iphlpapi', 'CreateProxyArpEntry', 'DWORD',[
			["DWORD","dwAddress","in"],
			["DWORD","dwMask","in"],
			["DWORD","dwIfIndex","in"],
			])

		railgun.add_function( 'iphlpapi', 'DeleteIPAddress', 'DWORD',[
			["DWORD","NTEContext","in"],
			])

		railgun.add_function( 'iphlpapi', 'DeleteProxyArpEntry', 'DWORD',[
			["DWORD","dwAddress","in"],
			["DWORD","dwMask","in"],
			["DWORD","dwIfIndex","in"],
			])

		railgun.add_function( 'iphlpapi', 'FlushIpNetTable', 'DWORD',[
			["DWORD","dwIfIndex","in"],
			])

		railgun.add_function( 'iphlpapi', 'GetAdapterIndex', 'DWORD',[
			["PWCHAR","AdapterName","in"],
			["PDWORD","IfIndex","inout"],
			])

		railgun.add_function( 'iphlpapi', 'GetBestInterface', 'DWORD',[
			["DWORD","dwDestAddr","in"],
			["PDWORD","pdwBestIfIndex","inout"],
			])

		railgun.add_function( 'iphlpapi', 'GetBestInterfaceEx', 'DWORD',[
			["PBLOB","pDestAddr","in"],
			["PDWORD","pdwBestIfIndex","inout"],
			])

		railgun.add_function( 'iphlpapi', 'GetFriendlyIfIndex', 'DWORD',[
			["DWORD","IfIndex","in"],
			])

		railgun.add_function( 'iphlpapi', 'GetNumberOfInterfaces', 'DWORD',[
			["PDWORD","pdwNumIf","inout"],
			])

		railgun.add_function( 'iphlpapi', 'GetRTTAndHopCount', 'BOOL',[
			["DWORD","DestIpAddress","in"],
			["PDWORD","HopCount","inout"],
			["DWORD","MaxHops","in"],
			["PDWORD","RTT","inout"],
			])

		railgun.add_function( 'iphlpapi', 'NotifyAddrChange', 'DWORD',[
			["PDWORD","Handle","inout"],
			["PBLOB","overlapped","in"],
			])

		railgun.add_function( 'iphlpapi', 'NotifyRouteChange', 'DWORD',[
			["PDWORD","Handle","inout"],
			["PBLOB","overlapped","in"],
			])

		railgun.add_function( 'iphlpapi', 'SendARP', 'DWORD',[
			["DWORD","DestIP","in"],
			["DWORD","SrcIP","in"],
			["PBLOB","pMacAddr","out"],
			["PDWORD","PhyAddrLen","inout"],
			])

		railgun.add_function( 'iphlpapi', 'SetIpTTL', 'DWORD',[
			["DWORD","nTTL","in"],
			])


		railgun.add_dll('advapi32','advapi32')
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
			["PBLOB","PrincipalSelfSid","in"],
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
			["PBLOB","PrincipalSelfSid","in"],
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
			["PBLOB","PrincipalSelfSid","in"],
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
			["PBLOB","PrincipalSelfSid","in"],
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
			["PBLOB","PrincipalSelfSid","in"],
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
			["PBLOB","PrincipalSelfSid","in"],
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
			["PBLOB","PrincipalSelfSid","in"],
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
			["PBLOB","PrincipalSelfSid","in"],
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
			["PBLOB","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessAllowedAceEx', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","AccessMask","in"],
			["PBLOB","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessAllowedObjectAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","AccessMask","in"],
			["PBLOB","ObjectTypeGuid","in"],
			["PBLOB","InheritedObjectTypeGuid","in"],
			["PBLOB","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessDeniedAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AccessMask","in"],
			["PBLOB","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessDeniedAceEx', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","AccessMask","in"],
			["PBLOB","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'AddAccessDeniedObjectAce', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","AccessMask","in"],
			["PBLOB","ObjectTypeGuid","in"],
			["PBLOB","InheritedObjectTypeGuid","in"],
			["PBLOB","pSid","in"],
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
			["PBLOB","pSid","in"],
			["BOOL","bAuditSuccess","in"],
			["BOOL","bAuditFailure","in"],
			])

		railgun.add_function( 'advapi32', 'AddAuditAccessAceEx', 'BOOL',[
			["PBLOB","pAcl","inout"],
			["DWORD","dwAceRevision","in"],
			["DWORD","AceFlags","in"],
			["DWORD","dwAccessMask","in"],
			["PBLOB","pSid","in"],
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
			["PBLOB","pSid","in"],
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
			["PBLOB","pSid","out"],
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

		railgun.add_function( 'advapi32', 'CopySid', 'BOOL',[
			["DWORD","nDestinationSidLength","in"],
			["PBLOB","pDestinationSid","out"],
			["PBLOB","pSourceSid","in"],
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
			["PBLOB","pSid1","in"],
			["PBLOB","pSid2","in"],
			["PBLOB","pfEqual","out"],
			])

		railgun.add_function( 'advapi32', 'EqualPrefixSid', 'BOOL',[
			["PBLOB","pSid1","in"],
			["PBLOB","pSid2","in"],
			])

		railgun.add_function( 'advapi32', 'EqualSid', 'BOOL',[
			["PBLOB","pSid1","in"],
			["PBLOB","pSid2","in"],
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
			["PBLOB","pSid","in"],
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
			["PBLOB","pSid","in"],
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
			["PBLOB","pSid","in"],
			])

		railgun.add_function( 'advapi32', 'IsWellKnownSid', 'BOOL',[
			["PBLOB","pSid","in"],
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
			["PBLOB","ppLogonSid","out"],
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
			["PBLOB","ppLogonSid","out"],
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
			["PBLOB","Sid","in"],
			["PCHAR","Name","out"],
			["PDWORD","cchName","inout"],
			["PCHAR","ReferencedDomainName","out"],
			["PDWORD","cchReferencedDomainName","inout"],
			["PBLOB","peUse","out"],
			])

		railgun.add_function( 'advapi32', 'LookupAccountSidW', 'BOOL',[
			["PWCHAR","lpSystemName","in"],
			["PBLOB","Sid","in"],
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
			["PBLOB","lpUserSid","in"],
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
			["PBLOB","lpUserSid","in"],
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


		railgun.add_dll('kernel32','kernel32')
		railgun.add_function( 'kernel32', 'ActivateActCtx', 'BOOL',[
			["DWORD","hActCtx","inout"],
			["PBLOB","lpCookie","out"],
			])

		railgun.add_function( 'kernel32', 'AddAtomA', 'WORD',[
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'AddAtomW', 'WORD',[
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'AddRefActCtx', 'VOID',[
			["DWORD","hActCtx","inout"],
			])

		railgun.add_function( 'kernel32', 'AllocateUserPhysicalPages', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","NumberOfPages","inout"],
			["PBLOB","PageArray","out"],
			])

		railgun.add_function( 'kernel32', 'AreFileApisANSI', 'BOOL',[
			])

		railgun.add_function( 'kernel32', 'AssignProcessToJobObject', 'BOOL',[
			["DWORD","hJob","in"],
			["DWORD","hProcess","in"],
			])

		railgun.add_function( 'kernel32', 'BackupRead', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PDWORD","lpNumberOfBytesRead","out"],
			["BOOL","bAbort","in"],
			["BOOL","bProcessSecurity","in"],
			["PBLOB","lpContext","inout"],
			])

		railgun.add_function( 'kernel32', 'BackupSeek', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwLowBytesToSeek","in"],
			["DWORD","dwHighBytesToSeek","in"],
			["PDWORD","lpdwLowByteSeeked","out"],
			["PDWORD","lpdwHighByteSeeked","out"],
			["PBLOB","lpContext","inout"],
			])

		railgun.add_function( 'kernel32', 'BackupWrite', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","nNumberOfBytesToWrite","in"],
			["PDWORD","lpNumberOfBytesWritten","out"],
			["BOOL","bAbort","in"],
			["BOOL","bProcessSecurity","in"],
			["PBLOB","lpContext","inout"],
			])

		railgun.add_function( 'kernel32', 'Beep', 'BOOL',[
			["DWORD","dwFreq","in"],
			["DWORD","dwDuration","in"],
			])

		railgun.add_function( 'kernel32', 'BeginUpdateResourceA', 'DWORD',[
			["PCHAR","pFileName","in"],
			["BOOL","bDeleteExistingResources","in"],
			])

		railgun.add_function( 'kernel32', 'BeginUpdateResourceW', 'DWORD',[
			["PWCHAR","pFileName","in"],
			["BOOL","bDeleteExistingResources","in"],
			])

		railgun.add_function( 'kernel32', 'BindIoCompletionCallback', 'BOOL',[
			["DWORD","FileHandle","in"],
			["PBLOB","Function","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'kernel32', 'BuildCommDCBA', 'BOOL',[
			["PCHAR","lpDef","in"],
			["PBLOB","lpDCB","out"],
			])

		railgun.add_function( 'kernel32', 'BuildCommDCBAndTimeoutsA', 'BOOL',[
			["PCHAR","lpDef","in"],
			["PBLOB","lpDCB","out"],
			["PBLOB","lpCommTimeouts","out"],
			])

		railgun.add_function( 'kernel32', 'BuildCommDCBAndTimeoutsW', 'BOOL',[
			["PWCHAR","lpDef","in"],
			["PBLOB","lpDCB","out"],
			["PBLOB","lpCommTimeouts","out"],
			])

		railgun.add_function( 'kernel32', 'BuildCommDCBW', 'BOOL',[
			["PWCHAR","lpDef","in"],
			["PBLOB","lpDCB","out"],
			])

		railgun.add_function( 'kernel32', 'CallNamedPipeA', 'BOOL',[
			["PCHAR","lpNamedPipeName","in"],
			["PBLOB","lpInBuffer","in"],
			["DWORD","nInBufferSize","in"],
			["PBLOB","lpOutBuffer","out"],
			["DWORD","nOutBufferSize","in"],
			["PDWORD","lpBytesRead","out"],
			["DWORD","nTimeOut","in"],
			])

		railgun.add_function( 'kernel32', 'CallNamedPipeW', 'BOOL',[
			["PWCHAR","lpNamedPipeName","in"],
			["PBLOB","lpInBuffer","in"],
			["DWORD","nInBufferSize","in"],
			["PBLOB","lpOutBuffer","out"],
			["DWORD","nOutBufferSize","in"],
			["PDWORD","lpBytesRead","out"],
			["DWORD","nTimeOut","in"],
			])

		railgun.add_function( 'kernel32', 'CancelDeviceWakeupRequest', 'BOOL',[
			["DWORD","hDevice","in"],
			])

		railgun.add_function( 'kernel32', 'CancelIo', 'BOOL',[
			["DWORD","hFile","in"],
			])

		railgun.add_function( 'kernel32', 'CancelTimerQueueTimer', 'BOOL',[
			["DWORD","TimerQueue","in"],
			["DWORD","Timer","in"],
			])

		railgun.add_function( 'kernel32', 'CancelWaitableTimer', 'BOOL',[
			["DWORD","hTimer","in"],
			])

		railgun.add_function( 'kernel32', 'ChangeTimerQueueTimer', 'BOOL',[
			["DWORD","TimerQueue","in"],
			["DWORD","Timer","inout"],
			["DWORD","DueTime","in"],
			["DWORD","Period","in"],
			])

		railgun.add_function( 'kernel32', 'CheckNameLegalDOS8Dot3A', 'BOOL',[
			["PCHAR","lpName","in"],
			["PCHAR","lpOemName","out"],
			["DWORD","OemNameSize","in"],
			["PBLOB","pbNameContainsSpaces","out"],
			["PBLOB","pbNameLegal","out"],
			])

		railgun.add_function( 'kernel32', 'CheckNameLegalDOS8Dot3W', 'BOOL',[
			["PWCHAR","lpName","in"],
			["PCHAR","lpOemName","out"],
			["DWORD","OemNameSize","in"],
			["PBLOB","pbNameContainsSpaces","out"],
			["PBLOB","pbNameLegal","out"],
			])

		railgun.add_function( 'kernel32', 'CheckRemoteDebuggerPresent', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","pbDebuggerPresent","out"],
			])

		railgun.add_function( 'kernel32', 'ClearCommBreak', 'BOOL',[
			["DWORD","hFile","in"],
			])

		railgun.add_function( 'kernel32', 'ClearCommError', 'BOOL',[
			["DWORD","hFile","in"],
			["PDWORD","lpErrors","out"],
			["PBLOB","lpStat","out"],
			])

		railgun.add_function( 'kernel32', 'CloseHandle', 'BOOL',[
			["DWORD","hObject","in"],
			])

		railgun.add_function( 'kernel32', 'CommConfigDialogA', 'BOOL',[
			["PCHAR","lpszName","in"],
			["DWORD","hWnd","in"],
			["PBLOB","lpCC","inout"],
			])

		railgun.add_function( 'kernel32', 'CommConfigDialogW', 'BOOL',[
			["PWCHAR","lpszName","in"],
			["DWORD","hWnd","in"],
			["PBLOB","lpCC","inout"],
			])

		railgun.add_function( 'kernel32', 'CompareFileTime', 'DWORD',[
			["PBLOB","lpFileTime1","in"],
			["PBLOB","lpFileTime2","in"],
			])

		railgun.add_function( 'kernel32', 'ConnectNamedPipe', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'ContinueDebugEvent', 'BOOL',[
			["DWORD","dwProcessId","in"],
			["DWORD","dwThreadId","in"],
			["DWORD","dwContinueStatus","in"],
			])

		railgun.add_function( 'kernel32', 'ConvertFiberToThread', 'BOOL',[
			])

		railgun.add_function( 'kernel32', 'CopyFileA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			["BOOL","bFailIfExists","in"],
			])

		railgun.add_function( 'kernel32', 'CopyFileExA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			["PBLOB","lpProgressRoutine","in"],
			["PBLOB","lpData","in"],
			["PBLOB","pbCancel","in"],
			["DWORD","dwCopyFlags","in"],
			])

		railgun.add_function( 'kernel32', 'CopyFileExW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			["PBLOB","lpProgressRoutine","in"],
			["PBLOB","lpData","in"],
			["PBLOB","pbCancel","in"],
			["DWORD","dwCopyFlags","in"],
			])

		railgun.add_function( 'kernel32', 'CopyFileW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			["BOOL","bFailIfExists","in"],
			])

		railgun.add_function( 'kernel32', 'CreateActCtxA', 'DWORD',[
			["PBLOB","pActCtx","in"],
			])

		railgun.add_function( 'kernel32', 'CreateActCtxW', 'DWORD',[
			["PBLOB","pActCtx","in"],
			])

		railgun.add_function( 'kernel32', 'CreateDirectoryA', 'BOOL',[
			["PCHAR","lpPathName","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'CreateDirectoryExA', 'BOOL',[
			["PCHAR","lpTemplateDirectory","in"],
			["PCHAR","lpNewDirectory","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'CreateDirectoryExW', 'BOOL',[
			["PWCHAR","lpTemplateDirectory","in"],
			["PWCHAR","lpNewDirectory","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'CreateDirectoryW', 'BOOL',[
			["PWCHAR","lpPathName","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'CreateEventA', 'DWORD',[
			["PBLOB","lpEventAttributes","in"],
			["BOOL","bManualReset","in"],
			["BOOL","bInitialState","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateEventW', 'DWORD',[
			["PBLOB","lpEventAttributes","in"],
			["BOOL","bManualReset","in"],
			["BOOL","bInitialState","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateFileA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["DWORD","dwDesiredAccess","in"],
			["DWORD","dwShareMode","in"],
			["PBLOB","lpSecurityAttributes","in"],
			["DWORD","dwCreationDisposition","in"],
			["DWORD","dwFlagsAndAttributes","in"],
			["DWORD","hTemplateFile","in"],
			])

		railgun.add_function( 'kernel32', 'CreateFileMappingA', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpFileMappingAttributes","in"],
			["DWORD","flProtect","in"],
			["DWORD","dwMaximumSizeHigh","in"],
			["DWORD","dwMaximumSizeLow","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateFileMappingW', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpFileMappingAttributes","in"],
			["DWORD","flProtect","in"],
			["DWORD","dwMaximumSizeHigh","in"],
			["DWORD","dwMaximumSizeLow","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateFileW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["DWORD","dwDesiredAccess","in"],
			["DWORD","dwShareMode","in"],
			["PBLOB","lpSecurityAttributes","in"],
			["DWORD","dwCreationDisposition","in"],
			["DWORD","dwFlagsAndAttributes","in"],
			["DWORD","hTemplateFile","in"],
			])

		railgun.add_function( 'kernel32', 'CreateHardLinkA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["PCHAR","lpExistingFileName","in"],
			["PBLOB","lpSecurityAttributes","inout"],
			])

		railgun.add_function( 'kernel32', 'CreateHardLinkW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["PWCHAR","lpExistingFileName","in"],
			["PBLOB","lpSecurityAttributes","inout"],
			])

		railgun.add_function( 'kernel32', 'CreateIoCompletionPort', 'DWORD',[
			["DWORD","FileHandle","in"],
			["DWORD","ExistingCompletionPort","in"],
			["PDWORD","CompletionKey","in"],
			["DWORD","NumberOfConcurrentThreads","in"],
			])

		railgun.add_function( 'kernel32', 'CreateJobObjectA', 'DWORD',[
			["PBLOB","lpJobAttributes","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateJobObjectW', 'DWORD',[
			["PBLOB","lpJobAttributes","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateJobSet', 'BOOL',[
			["DWORD","NumJob","in"],
			["PBLOB","UserJobSet","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'kernel32', 'CreateMailslotA', 'DWORD',[
			["PCHAR","lpName","in"],
			["DWORD","nMaxMessageSize","in"],
			["DWORD","lReadTimeout","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'CreateMailslotW', 'DWORD',[
			["PWCHAR","lpName","in"],
			["DWORD","nMaxMessageSize","in"],
			["DWORD","lReadTimeout","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'CreateMemoryResourceNotification', 'DWORD',[
			["PDWORD","NotificationType","in"],
			])

		railgun.add_function( 'kernel32', 'CreateMutexA', 'DWORD',[
			["PBLOB","lpMutexAttributes","in"],
			["BOOL","bInitialOwner","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateMutexW', 'DWORD',[
			["PBLOB","lpMutexAttributes","in"],
			["BOOL","bInitialOwner","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateNamedPipeA', 'DWORD',[
			["PCHAR","lpName","in"],
			["DWORD","dwOpenMode","in"],
			["DWORD","dwPipeMode","in"],
			["DWORD","nMaxInstances","in"],
			["DWORD","nOutBufferSize","in"],
			["DWORD","nInBufferSize","in"],
			["DWORD","nDefaultTimeOut","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'CreateNamedPipeW', 'DWORD',[
			["PWCHAR","lpName","in"],
			["DWORD","dwOpenMode","in"],
			["DWORD","dwPipeMode","in"],
			["DWORD","nMaxInstances","in"],
			["DWORD","nOutBufferSize","in"],
			["DWORD","nInBufferSize","in"],
			["DWORD","nDefaultTimeOut","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'CreatePipe', 'BOOL',[
			["PDWORD","hReadPipe","out"],
			["PDWORD","hWritePipe","out"],
			["PBLOB","lpPipeAttributes","in"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'CreateProcessA', 'BOOL',[
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

		railgun.add_function( 'kernel32', 'CreateProcessW', 'BOOL',[
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

		railgun.add_function( 'kernel32', 'CreateRemoteThread', 'DWORD',[
			["DWORD","hProcess","in"],
			["PBLOB","lpThreadAttributes","in"],
			["DWORD","dwStackSize","in"],
			["PBLOB","lpStartAddress","in"],
			["PBLOB","lpParameter","in"],
			["DWORD","dwCreationFlags","in"],
			["PDWORD","lpThreadId","out"],
			])

		railgun.add_function( 'kernel32', 'CreateSemaphoreA', 'DWORD',[
			["PBLOB","lpSemaphoreAttributes","in"],
			["DWORD","lInitialCount","in"],
			["DWORD","lMaximumCount","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateSemaphoreW', 'DWORD',[
			["PBLOB","lpSemaphoreAttributes","in"],
			["DWORD","lInitialCount","in"],
			["DWORD","lMaximumCount","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateTapePartition', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwPartitionMethod","in"],
			["DWORD","dwCount","in"],
			["DWORD","dwSize","in"],
			])

		railgun.add_function( 'kernel32', 'CreateThread', 'DWORD',[
			["PBLOB","lpThreadAttributes","in"],
			["DWORD","dwStackSize","in"],
			["PBLOB","lpStartAddress","in"],
			["PBLOB","lpParameter","in"],
			["DWORD","dwCreationFlags","in"],
			["PDWORD","lpThreadId","out"],
			])

		railgun.add_function( 'kernel32', 'CreateTimerQueue', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'CreateTimerQueueTimer', 'BOOL',[
			["PDWORD","phNewTimer","out"],
			["DWORD","TimerQueue","in"],
			["PBLOB","Callback","in"],
			["PBLOB","Parameter","in"],
			["DWORD","DueTime","in"],
			["DWORD","Period","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'kernel32', 'CreateWaitableTimerA', 'DWORD',[
			["PBLOB","lpTimerAttributes","in"],
			["BOOL","bManualReset","in"],
			["PCHAR","lpTimerName","in"],
			])

		railgun.add_function( 'kernel32', 'CreateWaitableTimerW', 'DWORD',[
			["PBLOB","lpTimerAttributes","in"],
			["BOOL","bManualReset","in"],
			["PWCHAR","lpTimerName","in"],
			])

		railgun.add_function( 'kernel32', 'DeactivateActCtx', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PDWORD","ulCookie","in"],
			])

		railgun.add_function( 'kernel32', 'DebugActiveProcess', 'BOOL',[
			["DWORD","dwProcessId","in"],
			])

		railgun.add_function( 'kernel32', 'DebugActiveProcessStop', 'BOOL',[
			["DWORD","dwProcessId","in"],
			])

		railgun.add_function( 'kernel32', 'DebugBreak', 'VOID',[
			])

		railgun.add_function( 'kernel32', 'DebugBreakProcess', 'BOOL',[
			["DWORD","Process","in"],
			])

		railgun.add_function( 'kernel32', 'DebugSetProcessKillOnExit', 'BOOL',[
			["BOOL","KillOnExit","in"],
			])

		railgun.add_function( 'kernel32', 'DefineDosDeviceA', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PCHAR","lpDeviceName","in"],
			["PCHAR","lpTargetPath","in"],
			])

		railgun.add_function( 'kernel32', 'DefineDosDeviceW', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PWCHAR","lpDeviceName","in"],
			["PWCHAR","lpTargetPath","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteAtom', 'WORD',[
			["WORD","nAtom","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteCriticalSection', 'VOID',[
			["PBLOB","lpCriticalSection","inout"],
			])

		railgun.add_function( 'kernel32', 'DeleteFiber', 'VOID',[
			["PBLOB","lpFiber","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteFileA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteFileW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteTimerQueue', 'BOOL',[
			["DWORD","TimerQueue","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteTimerQueueEx', 'BOOL',[
			["DWORD","TimerQueue","in"],
			["DWORD","CompletionEvent","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteTimerQueueTimer', 'BOOL',[
			["DWORD","TimerQueue","in"],
			["DWORD","Timer","in"],
			["DWORD","CompletionEvent","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteVolumeMountPointA', 'BOOL',[
			["PCHAR","lpszVolumeMountPoint","in"],
			])

		railgun.add_function( 'kernel32', 'DeleteVolumeMountPointW', 'BOOL',[
			["PWCHAR","lpszVolumeMountPoint","in"],
			])

		railgun.add_function( 'kernel32', 'DeviceIoControl', 'BOOL',[
			["DWORD","hDevice","in"],
			["DWORD","dwIoControlCode","in"],
			["PBLOB","lpInBuffer","in"],
			["DWORD","nInBufferSize","in"],
			["PBLOB","lpOutBuffer","out"],
			["DWORD","nOutBufferSize","in"],
			["PDWORD","lpBytesReturned","out"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'DisableThreadLibraryCalls', 'BOOL',[
			["DWORD","hLibModule","in"],
			])

		railgun.add_function( 'kernel32', 'DisconnectNamedPipe', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			])

		railgun.add_function( 'kernel32', 'DnsHostnameToComputerNameA', 'BOOL',[
			["PCHAR","Hostname","in"],
			["PCHAR","ComputerName","out"],
			["PDWORD","nSize","inout"],
			])

		railgun.add_function( 'kernel32', 'DnsHostnameToComputerNameW', 'BOOL',[
			["PWCHAR","Hostname","in"],
			["PWCHAR","ComputerName","out"],
			["PDWORD","nSize","inout"],
			])

		railgun.add_function( 'kernel32', 'DosDateTimeToFileTime', 'BOOL',[
			["WORD","wFatDate","in"],
			["WORD","wFatTime","in"],
			["PBLOB","lpFileTime","out"],
			])

		railgun.add_function( 'kernel32', 'DuplicateHandle', 'BOOL',[
			["DWORD","hSourceProcessHandle","in"],
			["DWORD","hSourceHandle","in"],
			["DWORD","hTargetProcessHandle","in"],
			["PDWORD","lpTargetHandle","out"],
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["DWORD","dwOptions","in"],
			])

		railgun.add_function( 'kernel32', 'EndUpdateResourceA', 'BOOL',[
			["DWORD","hUpdate","in"],
			["BOOL","fDiscard","in"],
			])

		railgun.add_function( 'kernel32', 'EndUpdateResourceW', 'BOOL',[
			["DWORD","hUpdate","in"],
			["BOOL","fDiscard","in"],
			])

		railgun.add_function( 'kernel32', 'EnterCriticalSection', 'VOID',[
			["PBLOB","lpCriticalSection","inout"],
			])

		railgun.add_function( 'kernel32', 'EnumResourceLanguagesA', 'BOOL',[
			["DWORD","hModule","in"],
			["PCHAR","lpType","in"],
			["PCHAR","lpName","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'kernel32', 'EnumResourceLanguagesW', 'BOOL',[
			["DWORD","hModule","in"],
			["PWCHAR","lpType","in"],
			["PWCHAR","lpName","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'kernel32', 'EnumResourceNamesA', 'BOOL',[
			["DWORD","hModule","in"],
			["PCHAR","lpType","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'kernel32', 'EnumResourceNamesW', 'BOOL',[
			["DWORD","hModule","in"],
			["PWCHAR","lpType","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'kernel32', 'EnumResourceTypesA', 'BOOL',[
			["DWORD","hModule","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'kernel32', 'EnumResourceTypesW', 'BOOL',[
			["DWORD","hModule","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'kernel32', 'EnumSystemFirmwareTables', 'DWORD',[
			["DWORD","FirmwareTableProviderSignature","in"],
			["PBLOB","pFirmwareTableEnumBuffer","out"],
			["DWORD","BufferSize","in"],
			])

		railgun.add_function( 'kernel32', 'EraseTape', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwEraseType","in"],
			["BOOL","bImmediate","in"],
			])

		railgun.add_function( 'kernel32', 'EscapeCommFunction', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFunc","in"],
			])

		railgun.add_function( 'kernel32', 'ExitProcess', 'VOID',[
			["DWORD","uExitCode","in"],
			])

		railgun.add_function( 'kernel32', 'ExitThread', 'VOID',[
			["DWORD","dwExitCode","in"],
			])

		railgun.add_function( 'kernel32', 'ExpandEnvironmentStringsA', 'DWORD',[
			["PCHAR","lpSrc","in"],
			["PCHAR","lpDst","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'ExpandEnvironmentStringsW', 'DWORD',[
			["PWCHAR","lpSrc","in"],
			["PWCHAR","lpDst","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'FatalAppExitA', 'VOID',[
			["DWORD","uAction","in"],
			["PCHAR","lpMessageText","in"],
			])

		railgun.add_function( 'kernel32', 'FatalAppExitW', 'VOID',[
			["DWORD","uAction","in"],
			["PWCHAR","lpMessageText","in"],
			])

		railgun.add_function( 'kernel32', 'FatalExit', 'VOID',[
			["DWORD","ExitCode","in"],
			])

		railgun.add_function( 'kernel32', 'FileTimeToDosDateTime', 'BOOL',[
			["PBLOB","lpFileTime","in"],
			["PBLOB","lpFatDate","out"],
			["PBLOB","lpFatTime","out"],
			])

		railgun.add_function( 'kernel32', 'FileTimeToLocalFileTime', 'BOOL',[
			["PBLOB","lpFileTime","in"],
			["PBLOB","lpLocalFileTime","out"],
			])

		railgun.add_function( 'kernel32', 'FileTimeToSystemTime', 'BOOL',[
			["PBLOB","lpFileTime","in"],
			["PBLOB","lpSystemTime","out"],
			])

		railgun.add_function( 'kernel32', 'FindActCtxSectionGuid', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PBLOB","lpExtensionGuid","inout"],
			["DWORD","ulSectionId","in"],
			["PBLOB","lpGuidToFind","in"],
			["PBLOB","ReturnedData","out"],
			])

		railgun.add_function( 'kernel32', 'FindActCtxSectionStringA', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PBLOB","lpExtensionGuid","inout"],
			["DWORD","ulSectionId","in"],
			["PCHAR","lpStringToFind","in"],
			["PBLOB","ReturnedData","out"],
			])

		railgun.add_function( 'kernel32', 'FindActCtxSectionStringW', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PBLOB","lpExtensionGuid","inout"],
			["DWORD","ulSectionId","in"],
			["PWCHAR","lpStringToFind","in"],
			["PBLOB","ReturnedData","out"],
			])

		railgun.add_function( 'kernel32', 'FindAtomA', 'WORD',[
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'FindAtomW', 'WORD',[
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'FindClose', 'BOOL',[
			["DWORD","hFindFile","inout"],
			])

		railgun.add_function( 'kernel32', 'FindCloseChangeNotification', 'BOOL',[
			["DWORD","hChangeHandle","in"],
			])

		railgun.add_function( 'kernel32', 'FindFirstChangeNotificationA', 'DWORD',[
			["PCHAR","lpPathName","in"],
			["BOOL","bWatchSubtree","in"],
			["DWORD","dwNotifyFilter","in"],
			])

		railgun.add_function( 'kernel32', 'FindFirstChangeNotificationW', 'DWORD',[
			["PWCHAR","lpPathName","in"],
			["BOOL","bWatchSubtree","in"],
			["DWORD","dwNotifyFilter","in"],
			])

		railgun.add_function( 'kernel32', 'FindFirstFileA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["PBLOB","lpFindFileData","out"],
			])

		railgun.add_function( 'kernel32', 'FindFirstFileExA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["PBLOB","fInfoLevelId","in"],
			["PBLOB","lpFindFileData","out"],
			["PBLOB","fSearchOp","in"],
			["PBLOB","lpSearchFilter","inout"],
			["DWORD","dwAdditionalFlags","in"],
			])

		railgun.add_function( 'kernel32', 'FindFirstFileExW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","fInfoLevelId","in"],
			["PBLOB","lpFindFileData","out"],
			["PBLOB","fSearchOp","in"],
			["PBLOB","lpSearchFilter","inout"],
			["DWORD","dwAdditionalFlags","in"],
			])

		railgun.add_function( 'kernel32', 'FindFirstFileW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","lpFindFileData","out"],
			])

		railgun.add_function( 'kernel32', 'FindFirstStreamW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","InfoLevel","in"],
			["PBLOB","lpFindStreamData","out"],
			["DWORD","dwFlags","inout"],
			])

		railgun.add_function( 'kernel32', 'FindFirstVolumeA', 'DWORD',[
			["PCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'FindFirstVolumeMountPointA', 'DWORD',[
			["PCHAR","lpszRootPathName","in"],
			["PCHAR","lpszVolumeMountPoint","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'FindFirstVolumeMountPointW', 'DWORD',[
			["PWCHAR","lpszRootPathName","in"],
			["PWCHAR","lpszVolumeMountPoint","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'FindFirstVolumeW', 'DWORD',[
			["PWCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'FindNextChangeNotification', 'BOOL',[
			["DWORD","hChangeHandle","in"],
			])

		railgun.add_function( 'kernel32', 'FindNextFileA', 'BOOL',[
			["DWORD","hFindFile","in"],
			["PBLOB","lpFindFileData","out"],
			])

		railgun.add_function( 'kernel32', 'FindNextFileW', 'BOOL',[
			["DWORD","hFindFile","in"],
			["PBLOB","lpFindFileData","out"],
			])

		railgun.add_function( 'kernel32', 'FindNextStreamW', 'BOOL',[
			["DWORD","hFindStream","in"],
			["PBLOB","lpFindStreamData","out"],
			])

		railgun.add_function( 'kernel32', 'FindNextVolumeA', 'BOOL',[
			["DWORD","hFindVolume","inout"],
			["PCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'FindNextVolumeMountPointA', 'BOOL',[
			["DWORD","hFindVolumeMountPoint","in"],
			["PCHAR","lpszVolumeMountPoint","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'FindNextVolumeMountPointW', 'BOOL',[
			["DWORD","hFindVolumeMountPoint","in"],
			["PWCHAR","lpszVolumeMountPoint","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'FindNextVolumeW', 'BOOL',[
			["DWORD","hFindVolume","inout"],
			["PWCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'FindResourceA', 'DWORD',[
			["DWORD","hModule","in"],
			["PCHAR","lpName","in"],
			["PCHAR","lpType","in"],
			])

		railgun.add_function( 'kernel32', 'FindResourceExA', 'DWORD',[
			["DWORD","hModule","in"],
			["PCHAR","lpType","in"],
			["PCHAR","lpName","in"],
			["WORD","wLanguage","in"],
			])

		railgun.add_function( 'kernel32', 'FindResourceExW', 'DWORD',[
			["DWORD","hModule","in"],
			["PWCHAR","lpType","in"],
			["PWCHAR","lpName","in"],
			["WORD","wLanguage","in"],
			])

		railgun.add_function( 'kernel32', 'FindResourceW', 'DWORD',[
			["DWORD","hModule","in"],
			["PWCHAR","lpName","in"],
			["PWCHAR","lpType","in"],
			])

		railgun.add_function( 'kernel32', 'FindVolumeClose', 'BOOL',[
			["DWORD","hFindVolume","in"],
			])

		railgun.add_function( 'kernel32', 'FindVolumeMountPointClose', 'BOOL',[
			["DWORD","hFindVolumeMountPoint","in"],
			])

		railgun.add_function( 'kernel32', 'FlsAlloc', 'DWORD',[
			["PBLOB","lpCallback","in"],
			])

		railgun.add_function( 'kernel32', 'FlsFree', 'BOOL',[
			["DWORD","dwFlsIndex","in"],
			])

		railgun.add_function( 'kernel32', 'FlsSetValue', 'BOOL',[
			["DWORD","dwFlsIndex","in"],
			["PBLOB","lpFlsData","in"],
			])

		railgun.add_function( 'kernel32', 'FlushFileBuffers', 'BOOL',[
			["DWORD","hFile","in"],
			])

		railgun.add_function( 'kernel32', 'FlushInstructionCache', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpBaseAddress","in"],
			["DWORD","dwSize","in"],
			])

		railgun.add_function( 'kernel32', 'FlushViewOfFile', 'BOOL',[
			["PBLOB","lpBaseAddress","in"],
			["DWORD","dwNumberOfBytesToFlush","in"],
			])

		railgun.add_function( 'kernel32', 'FreeEnvironmentStringsA', 'BOOL',[
			["PBLOB","param0","in"],
			])

		railgun.add_function( 'kernel32', 'FreeEnvironmentStringsW', 'BOOL',[
			["PBLOB","param0","in"],
			])

		railgun.add_function( 'kernel32', 'FreeLibrary', 'BOOL',[
			["DWORD","hLibModule","in"],
			])

		railgun.add_function( 'kernel32', 'FreeLibraryAndExitThread', 'VOID',[
			["DWORD","hLibModule","in"],
			["DWORD","dwExitCode","in"],
			])

		railgun.add_function( 'kernel32', 'FreeResource', 'BOOL',[
			["DWORD","hResData","in"],
			])

		railgun.add_function( 'kernel32', 'FreeUserPhysicalPages', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","NumberOfPages","inout"],
			["PBLOB","PageArray","in"],
			])

		railgun.add_function( 'kernel32', 'GetAtomNameA', 'DWORD',[
			["WORD","nAtom","in"],
			["PCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetAtomNameW', 'DWORD',[
			["WORD","nAtom","in"],
			["PWCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetBinaryTypeA', 'BOOL',[
			["PCHAR","lpApplicationName","in"],
			["PDWORD","lpBinaryType","out"],
			])

		railgun.add_function( 'kernel32', 'GetBinaryTypeW', 'BOOL',[
			["PWCHAR","lpApplicationName","in"],
			["PDWORD","lpBinaryType","out"],
			])

		railgun.add_function( 'kernel32', 'GetCommConfig', 'BOOL',[
			["DWORD","hCommDev","in"],
			["PBLOB","lpCC","out"],
			["PDWORD","lpdwSize","inout"],
			])

		railgun.add_function( 'kernel32', 'GetCommMask', 'BOOL',[
			["DWORD","hFile","in"],
			["PDWORD","lpEvtMask","out"],
			])

		railgun.add_function( 'kernel32', 'GetCommModemStatus', 'BOOL',[
			["DWORD","hFile","in"],
			["PDWORD","lpModemStat","out"],
			])

		railgun.add_function( 'kernel32', 'GetCommProperties', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCommProp","out"],
			])

		railgun.add_function( 'kernel32', 'GetCommState', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpDCB","out"],
			])

		railgun.add_function( 'kernel32', 'GetCommTimeouts', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCommTimeouts","out"],
			])

		railgun.add_function( 'kernel32', 'GetCompressedFileSizeA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["PDWORD","lpFileSizeHigh","out"],
			])

		railgun.add_function( 'kernel32', 'GetCompressedFileSizeW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["PDWORD","lpFileSizeHigh","out"],
			])

		railgun.add_function( 'kernel32', 'GetComputerNameA', 'BOOL',[
			["PCHAR","lpBuffer","out"],
			["PDWORD","nSize","inout"],
			])

		railgun.add_function( 'kernel32', 'GetComputerNameExA', 'BOOL',[
			["DWORD","NameType","in"],
			["PCHAR","lpBuffer","out"],
			["PDWORD","nSize","inout"],
			])

		railgun.add_function( 'kernel32', 'GetComputerNameExW', 'BOOL',[
			["DWORD","NameType","in"],
			["PWCHAR","lpBuffer","out"],
			["PDWORD","nSize","inout"],
			])

		railgun.add_function( 'kernel32', 'GetComputerNameW', 'BOOL',[
			["PWCHAR","lpBuffer","out"],
			["PDWORD","nSize","inout"],
			])

		railgun.add_function( 'kernel32', 'GetCurrentActCtx', 'BOOL',[
			["PDWORD","lphActCtx","out"],
			])

		railgun.add_function( 'kernel32', 'GetCurrentDirectoryA', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GetCurrentDirectoryW', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GetCurrentProcess', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetCurrentProcessId', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetCurrentProcessorNumber', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetCurrentThread', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetCurrentThreadId', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetDefaultCommConfigA', 'BOOL',[
			["PCHAR","lpszName","in"],
			["PBLOB","lpCC","out"],
			["PDWORD","lpdwSize","inout"],
			])

		railgun.add_function( 'kernel32', 'GetDefaultCommConfigW', 'BOOL',[
			["PWCHAR","lpszName","in"],
			["PBLOB","lpCC","out"],
			["PDWORD","lpdwSize","inout"],
			])

		railgun.add_function( 'kernel32', 'GetDevicePowerState', 'BOOL',[
			["DWORD","hDevice","in"],
			["PBLOB","pfOn","out"],
			])

		railgun.add_function( 'kernel32', 'GetDiskFreeSpaceA', 'BOOL',[
			["PCHAR","lpRootPathName","in"],
			["PDWORD","lpSectorsPerCluster","out"],
			["PDWORD","lpBytesPerSector","out"],
			["PDWORD","lpNumberOfFreeClusters","out"],
			["PDWORD","lpTotalNumberOfClusters","out"],
			])

		railgun.add_function( 'kernel32', 'GetDiskFreeSpaceExA', 'BOOL',[
			["PCHAR","lpDirectoryName","in"],
			["PBLOB","lpFreeBytesAvailableToCaller","out"],
			["PBLOB","lpTotalNumberOfBytes","out"],
			["PBLOB","lpTotalNumberOfFreeBytes","out"],
			])

		railgun.add_function( 'kernel32', 'GetDiskFreeSpaceExW', 'BOOL',[
			["PWCHAR","lpDirectoryName","in"],
			["PBLOB","lpFreeBytesAvailableToCaller","out"],
			["PBLOB","lpTotalNumberOfBytes","out"],
			["PBLOB","lpTotalNumberOfFreeBytes","out"],
			])

		railgun.add_function( 'kernel32', 'GetDiskFreeSpaceW', 'BOOL',[
			["PWCHAR","lpRootPathName","in"],
			["PDWORD","lpSectorsPerCluster","out"],
			["PDWORD","lpBytesPerSector","out"],
			["PDWORD","lpNumberOfFreeClusters","out"],
			["PDWORD","lpTotalNumberOfClusters","out"],
			])

		railgun.add_function( 'kernel32', 'GetDllDirectoryA', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GetDllDirectoryW', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GetDriveTypeA', 'DWORD',[
			["PCHAR","lpRootPathName","in"],
			])

		railgun.add_function( 'kernel32', 'GetDriveTypeW', 'DWORD',[
			["PWCHAR","lpRootPathName","in"],
			])

		railgun.add_function( 'kernel32', 'GetEnvironmentVariableA', 'DWORD',[
			["PCHAR","lpName","in"],
			["PCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetEnvironmentVariableW', 'DWORD',[
			["PWCHAR","lpName","in"],
			["PWCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetExitCodeProcess', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","lpExitCode","out"],
			])

		railgun.add_function( 'kernel32', 'GetExitCodeThread', 'BOOL',[
			["DWORD","hThread","in"],
			["PDWORD","lpExitCode","out"],
			])

		railgun.add_function( 'kernel32', 'GetFileAttributesA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetFileAttributesExA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["PBLOB","fInfoLevelId","in"],
			["PBLOB","lpFileInformation","out"],
			])

		railgun.add_function( 'kernel32', 'GetFileAttributesExW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","fInfoLevelId","in"],
			["PBLOB","lpFileInformation","out"],
			])

		railgun.add_function( 'kernel32', 'GetFileAttributesW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetFileInformationByHandle', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpFileInformation","out"],
			])

		railgun.add_function( 'kernel32', 'GetFileSize', 'DWORD',[
			["DWORD","hFile","in"],
			["PDWORD","lpFileSizeHigh","out"],
			])

		railgun.add_function( 'kernel32', 'GetFileSizeEx', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpFileSize","out"],
			])

		railgun.add_function( 'kernel32', 'GetFileTime', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCreationTime","out"],
			["PBLOB","lpLastAccessTime","out"],
			["PBLOB","lpLastWriteTime","out"],
			])

		railgun.add_function( 'kernel32', 'GetFileType', 'DWORD',[
			["DWORD","hFile","in"],
			])

		railgun.add_function( 'kernel32', 'GetFirmwareEnvironmentVariableA', 'DWORD',[
			["PCHAR","lpName","in"],
			["PCHAR","lpGuid","in"],
			["PBLOB","pBuffer","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetFirmwareEnvironmentVariableW', 'DWORD',[
			["PWCHAR","lpName","in"],
			["PWCHAR","lpGuid","in"],
			["PBLOB","pBuffer","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetFullPathNameA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			["PBLOB","lpFilePart","out"],
			])

		railgun.add_function( 'kernel32', 'GetFullPathNameW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			["PBLOB","lpFilePart","out"],
			])

		railgun.add_function( 'kernel32', 'GetHandleInformation', 'BOOL',[
			["DWORD","hObject","in"],
			["PDWORD","lpdwFlags","out"],
			])

		railgun.add_function( 'kernel32', 'GetLargePageMinimum', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetLastError', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetLocalTime', 'VOID',[
			["PBLOB","lpSystemTime","out"],
			])

		railgun.add_function( 'kernel32', 'GetLogicalDriveStringsA', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GetLogicalDriveStringsW', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GetLogicalDrives', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetLogicalProcessorInformation', 'BOOL',[
			["PBLOB","Buffer","out"],
			["PDWORD","ReturnedLength","inout"],
			])

		railgun.add_function( 'kernel32', 'GetLongPathNameA', 'DWORD',[
			["PCHAR","lpszShortPath","in"],
			["PCHAR","lpszLongPath","out"],
			["DWORD","cchBuffer","in"],
			])

		railgun.add_function( 'kernel32', 'GetLongPathNameW', 'DWORD',[
			["PWCHAR","lpszShortPath","in"],
			["PWCHAR","lpszLongPath","out"],
			["DWORD","cchBuffer","in"],
			])

		railgun.add_function( 'kernel32', 'GetMailslotInfo', 'BOOL',[
			["DWORD","hMailslot","in"],
			["PDWORD","lpMaxMessageSize","out"],
			["PDWORD","lpNextSize","out"],
			["PDWORD","lpMessageCount","out"],
			["PDWORD","lpReadTimeout","out"],
			])

		railgun.add_function( 'kernel32', 'GetModuleFileNameA', 'DWORD',[
			["DWORD","hModule","in"],
			["PBLOB","lpFilename","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetModuleFileNameW', 'DWORD',[
			["DWORD","hModule","in"],
			["PBLOB","lpFilename","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetModuleHandleA', 'DWORD',[
			["PCHAR","lpModuleName","in"],
			])

		railgun.add_function( 'kernel32', 'GetModuleHandleExA', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PCHAR","lpModuleName","in"],
			["PDWORD","phModule","out"],
			])

		railgun.add_function( 'kernel32', 'GetModuleHandleExW', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PWCHAR","lpModuleName","in"],
			["PDWORD","phModule","out"],
			])

		railgun.add_function( 'kernel32', 'GetModuleHandleW', 'DWORD',[
			["PWCHAR","lpModuleName","in"],
			])

		railgun.add_function( 'kernel32', 'GetNamedPipeHandleStateA', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PDWORD","lpState","out"],
			["PDWORD","lpCurInstances","out"],
			["PDWORD","lpMaxCollectionCount","out"],
			["PDWORD","lpCollectDataTimeout","out"],
			["PCHAR","lpUserName","out"],
			["DWORD","nMaxUserNameSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetNamedPipeHandleStateW', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PDWORD","lpState","out"],
			["PDWORD","lpCurInstances","out"],
			["PDWORD","lpMaxCollectionCount","out"],
			["PDWORD","lpCollectDataTimeout","out"],
			["PWCHAR","lpUserName","out"],
			["DWORD","nMaxUserNameSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetNamedPipeInfo', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PDWORD","lpFlags","out"],
			["PDWORD","lpOutBufferSize","out"],
			["PDWORD","lpInBufferSize","out"],
			["PDWORD","lpMaxInstances","out"],
			])

		railgun.add_function( 'kernel32', 'GetNativeSystemInfo', 'VOID',[
			["PBLOB","lpSystemInfo","out"],
			])

		railgun.add_function( 'kernel32', 'GetNumaAvailableMemoryNode', 'BOOL',[
			["BYTE","Node","in"],
			["PBLOB","AvailableBytes","out"],
			])

		railgun.add_function( 'kernel32', 'GetNumaHighestNodeNumber', 'BOOL',[
			["PDWORD","HighestNodeNumber","out"],
			])

		railgun.add_function( 'kernel32', 'GetNumaNodeProcessorMask', 'BOOL',[
			["BYTE","Node","in"],
			["PBLOB","ProcessorMask","out"],
			])

		railgun.add_function( 'kernel32', 'GetNumaProcessorNode', 'BOOL',[
			["BYTE","Processor","in"],
			["PBLOB","NodeNumber","out"],
			])

		railgun.add_function( 'kernel32', 'GetOverlappedResult', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpOverlapped","in"],
			["PDWORD","lpNumberOfBytesTransferred","out"],
			["BOOL","bWait","in"],
			])

		railgun.add_function( 'kernel32', 'GetPriorityClass', 'DWORD',[
			["DWORD","hProcess","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileIntA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["DWORD","nDefault","in"],
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileIntW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["DWORD","nDefault","in"],
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileSectionA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileSectionNamesA', 'DWORD',[
			["PCHAR","lpszReturnBuffer","out"],
			["DWORD","nSize","in"],
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileSectionNamesW', 'DWORD',[
			["PWCHAR","lpszReturnBuffer","out"],
			["DWORD","nSize","in"],
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileSectionW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileStringA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["PCHAR","lpDefault","in"],
			["PCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileStringW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["PWCHAR","lpDefault","in"],
			["PWCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileStructA', 'BOOL',[
			["PCHAR","lpszSection","in"],
			["PCHAR","lpszKey","in"],
			["PBLOB","lpStruct","out"],
			["DWORD","uSizeStruct","in"],
			["PCHAR","szFile","in"],
			])

		railgun.add_function( 'kernel32', 'GetPrivateProfileStructW', 'BOOL',[
			["PWCHAR","lpszSection","in"],
			["PWCHAR","lpszKey","in"],
			["PBLOB","lpStruct","out"],
			["DWORD","uSizeStruct","in"],
			["PWCHAR","szFile","in"],
			])

		railgun.add_function( 'kernel32', 'GetProcessAffinityMask', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpProcessAffinityMask","out"],
			["PBLOB","lpSystemAffinityMask","out"],
			])

		railgun.add_function( 'kernel32', 'GetProcessHandleCount', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","pdwHandleCount","out"],
			])

		railgun.add_function( 'kernel32', 'GetProcessHeap', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetProcessHeaps', 'DWORD',[
			["DWORD","NumberOfHeaps","in"],
			["PDWORD","ProcessHeaps","out"],
			])

		railgun.add_function( 'kernel32', 'GetProcessId', 'DWORD',[
			["DWORD","Process","in"],
			])

		railgun.add_function( 'kernel32', 'GetProcessIdOfThread', 'DWORD',[
			["DWORD","Thread","in"],
			])

		railgun.add_function( 'kernel32', 'GetProcessIoCounters', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpIoCounters","out"],
			])

		railgun.add_function( 'kernel32', 'GetProcessPriorityBoost', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","pDisablePriorityBoost","out"],
			])

		railgun.add_function( 'kernel32', 'GetProcessShutdownParameters', 'BOOL',[
			["PDWORD","lpdwLevel","out"],
			["PDWORD","lpdwFlags","out"],
			])

		railgun.add_function( 'kernel32', 'GetProcessTimes', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpCreationTime","out"],
			["PBLOB","lpExitTime","out"],
			["PBLOB","lpKernelTime","out"],
			["PBLOB","lpUserTime","out"],
			])

		railgun.add_function( 'kernel32', 'GetProcessVersion', 'DWORD',[
			["DWORD","ProcessId","in"],
			])

		railgun.add_function( 'kernel32', 'GetProcessWorkingSetSize', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","lpMinimumWorkingSetSize","out"],
			["PDWORD","lpMaximumWorkingSetSize","out"],
			])

		railgun.add_function( 'kernel32', 'GetProcessWorkingSetSizeEx', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","lpMinimumWorkingSetSize","out"],
			["PDWORD","lpMaximumWorkingSetSize","out"],
			["PDWORD","Flags","out"],
			])

		railgun.add_function( 'kernel32', 'GetProfileIntA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["DWORD","nDefault","in"],
			])

		railgun.add_function( 'kernel32', 'GetProfileIntW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["DWORD","nDefault","in"],
			])

		railgun.add_function( 'kernel32', 'GetProfileSectionA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetProfileSectionW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetProfileStringA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["PCHAR","lpDefault","in"],
			["PCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetProfileStringW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["PWCHAR","lpDefault","in"],
			["PWCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetQueuedCompletionStatus', 'BOOL',[
			["DWORD","CompletionPort","in"],
			["PDWORD","lpNumberOfBytesTransferred","out"],
			["PBLOB","lpCompletionKey","out"],
			["PBLOB","lpOverlapped","out"],
			["DWORD","dwMilliseconds","in"],
			])

		railgun.add_function( 'kernel32', 'GetShortPathNameA', 'DWORD',[
			["PCHAR","lpszLongPath","in"],
			["PCHAR","lpszShortPath","out"],
			["DWORD","cchBuffer","in"],
			])

		railgun.add_function( 'kernel32', 'GetShortPathNameW', 'DWORD',[
			["PWCHAR","lpszLongPath","in"],
			["PWCHAR","lpszShortPath","out"],
			["DWORD","cchBuffer","in"],
			])

		railgun.add_function( 'kernel32', 'GetStartupInfoA', 'VOID',[
			["PBLOB","lpStartupInfo","out"],
			])

		railgun.add_function( 'kernel32', 'GetStartupInfoW', 'VOID',[
			["PBLOB","lpStartupInfo","out"],
			])

		railgun.add_function( 'kernel32', 'GetStdHandle', 'DWORD',[
			["DWORD","nStdHandle","in"],
			])

		railgun.add_function( 'kernel32', 'GetSystemDirectoryA', 'DWORD',[
			["PCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetSystemDirectoryW', 'DWORD',[
			["PWCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetSystemFileCacheSize', 'BOOL',[
			["PDWORD","lpMinimumFileCacheSize","out"],
			["PDWORD","lpMaximumFileCacheSize","out"],
			["PDWORD","lpFlags","out"],
			])

		railgun.add_function( 'kernel32', 'GetSystemFirmwareTable', 'DWORD',[
			["DWORD","FirmwareTableProviderSignature","in"],
			["DWORD","FirmwareTableID","in"],
			["PBLOB","pFirmwareTableBuffer","out"],
			["DWORD","BufferSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetSystemInfo', 'VOID',[
			["PBLOB","lpSystemInfo","out"],
			])

		railgun.add_function( 'kernel32', 'GetSystemPowerStatus', 'BOOL',[
			["PBLOB","lpSystemPowerStatus","out"],
			])

		railgun.add_function( 'kernel32', 'GetSystemRegistryQuota', 'BOOL',[
			["PDWORD","pdwQuotaAllowed","out"],
			["PDWORD","pdwQuotaUsed","out"],
			])

		railgun.add_function( 'kernel32', 'GetSystemTime', 'VOID',[
			["PBLOB","lpSystemTime","out"],
			])

		railgun.add_function( 'kernel32', 'GetSystemTimeAdjustment', 'BOOL',[
			["PDWORD","lpTimeAdjustment","out"],
			["PDWORD","lpTimeIncrement","out"],
			["PBLOB","lpTimeAdjustmentDisabled","out"],
			])

		railgun.add_function( 'kernel32', 'GetSystemTimeAsFileTime', 'VOID',[
			["PBLOB","lpSystemTimeAsFileTime","out"],
			])

		railgun.add_function( 'kernel32', 'GetSystemTimes', 'BOOL',[
			["PBLOB","lpIdleTime","out"],
			["PBLOB","lpKernelTime","out"],
			["PBLOB","lpUserTime","out"],
			])

		railgun.add_function( 'kernel32', 'GetSystemWindowsDirectoryA', 'DWORD',[
			["PCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetSystemWindowsDirectoryW', 'DWORD',[
			["PWCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetSystemWow64DirectoryA', 'DWORD',[
			["PCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetSystemWow64DirectoryW', 'DWORD',[
			["PWCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetTapeParameters', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwOperation","in"],
			["PDWORD","lpdwSize","inout"],
			["PBLOB","lpTapeInformation","out"],
			])

		railgun.add_function( 'kernel32', 'GetTapePosition', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwPositionType","in"],
			["PDWORD","lpdwPartition","out"],
			["PDWORD","lpdwOffsetLow","out"],
			["PDWORD","lpdwOffsetHigh","out"],
			])

		railgun.add_function( 'kernel32', 'GetTapeStatus', 'DWORD',[
			["DWORD","hDevice","in"],
			])

		railgun.add_function( 'kernel32', 'GetTempFileNameA', 'DWORD',[
			["PCHAR","lpPathName","in"],
			["PCHAR","lpPrefixString","in"],
			["DWORD","uUnique","in"],
			["PCHAR","lpTempFileName","out"],
			])

		railgun.add_function( 'kernel32', 'GetTempFileNameW', 'DWORD',[
			["PWCHAR","lpPathName","in"],
			["PWCHAR","lpPrefixString","in"],
			["DWORD","uUnique","in"],
			["PWCHAR","lpTempFileName","out"],
			])

		railgun.add_function( 'kernel32', 'GetTempPathA', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GetTempPathW', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GetThreadContext', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","lpContext","inout"],
			])

		railgun.add_function( 'kernel32', 'GetThreadIOPendingFlag', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","lpIOIsPending","out"],
			])

		railgun.add_function( 'kernel32', 'GetThreadId', 'DWORD',[
			["DWORD","Thread","in"],
			])

		railgun.add_function( 'kernel32', 'GetThreadPriority', 'DWORD',[
			["DWORD","hThread","in"],
			])

		railgun.add_function( 'kernel32', 'GetThreadPriorityBoost', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","pDisablePriorityBoost","out"],
			])

		railgun.add_function( 'kernel32', 'GetThreadSelectorEntry', 'BOOL',[
			["DWORD","hThread","in"],
			["DWORD","dwSelector","in"],
			["PBLOB","lpSelectorEntry","out"],
			])

		railgun.add_function( 'kernel32', 'GetThreadTimes', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","lpCreationTime","out"],
			["PBLOB","lpExitTime","out"],
			["PBLOB","lpKernelTime","out"],
			["PBLOB","lpUserTime","out"],
			])

		railgun.add_function( 'kernel32', 'GetTickCount', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetTimeZoneInformation', 'DWORD',[
			["PBLOB","lpTimeZoneInformation","out"],
			])

		railgun.add_function( 'kernel32', 'GetVersion', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'GetVersionExA', 'BOOL',[
			["PBLOB","lpVersionInformation","inout"],
			])

		railgun.add_function( 'kernel32', 'GetVersionExW', 'BOOL',[
			["PBLOB","lpVersionInformation","inout"],
			])

		railgun.add_function( 'kernel32', 'GetVolumeInformationA', 'BOOL',[
			["PCHAR","lpRootPathName","in"],
			["PCHAR","lpVolumeNameBuffer","out"],
			["DWORD","nVolumeNameSize","in"],
			["PDWORD","lpVolumeSerialNumber","out"],
			["PDWORD","lpMaximumComponentLength","out"],
			["PDWORD","lpFileSystemFlags","out"],
			["PCHAR","lpFileSystemNameBuffer","out"],
			["DWORD","nFileSystemNameSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetVolumeInformationW', 'BOOL',[
			["PWCHAR","lpRootPathName","in"],
			["PWCHAR","lpVolumeNameBuffer","out"],
			["DWORD","nVolumeNameSize","in"],
			["PDWORD","lpVolumeSerialNumber","out"],
			["PDWORD","lpMaximumComponentLength","out"],
			["PDWORD","lpFileSystemFlags","out"],
			["PWCHAR","lpFileSystemNameBuffer","out"],
			["DWORD","nFileSystemNameSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetVolumeNameForVolumeMountPointA', 'BOOL',[
			["PCHAR","lpszVolumeMountPoint","in"],
			["PCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'GetVolumeNameForVolumeMountPointW', 'BOOL',[
			["PWCHAR","lpszVolumeMountPoint","in"],
			["PWCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'GetVolumePathNameA', 'BOOL',[
			["PCHAR","lpszFileName","in"],
			["PCHAR","lpszVolumePathName","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'GetVolumePathNameW', 'BOOL',[
			["PWCHAR","lpszFileName","in"],
			["PWCHAR","lpszVolumePathName","out"],
			["DWORD","cchBufferLength","in"],
			])

		railgun.add_function( 'kernel32', 'GetVolumePathNamesForVolumeNameA', 'BOOL',[
			["PCHAR","lpszVolumeName","in"],
			["PBLOB","lpszVolumePathNames","out"],
			["DWORD","cchBufferLength","in"],
			["PDWORD","lpcchReturnLength","out"],
			])

		railgun.add_function( 'kernel32', 'GetVolumePathNamesForVolumeNameW', 'BOOL',[
			["PWCHAR","lpszVolumeName","in"],
			["PBLOB","lpszVolumePathNames","out"],
			["DWORD","cchBufferLength","in"],
			["PDWORD","lpcchReturnLength","out"],
			])

		railgun.add_function( 'kernel32', 'GetWindowsDirectoryA', 'DWORD',[
			["PCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetWindowsDirectoryW', 'DWORD',[
			["PWCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])

		railgun.add_function( 'kernel32', 'GetWriteWatch', 'DWORD',[
			["DWORD","dwFlags","in"],
			["PBLOB","lpBaseAddress","in"],
			["DWORD","dwRegionSize","in"],
			["PBLOB","lpAddresses","out"],
			["PBLOB","lpdwCount","inout"],
			["PDWORD","lpdwGranularity","out"],
			])

		railgun.add_function( 'kernel32', 'GlobalAddAtomA', 'WORD',[
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalAddAtomW', 'WORD',[
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalAlloc', 'DWORD',[
			["DWORD","uFlags","in"],
			["DWORD","dwBytes","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalCompact', 'DWORD',[
			["DWORD","dwMinFree","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalDeleteAtom', 'WORD',[
			["WORD","nAtom","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalFindAtomA', 'WORD',[
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalFindAtomW', 'WORD',[
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalFix', 'VOID',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalFlags', 'DWORD',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalFree', 'DWORD',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalGetAtomNameA', 'DWORD',[
			["WORD","nAtom","in"],
			["PCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalGetAtomNameW', 'DWORD',[
			["WORD","nAtom","in"],
			["PWCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalHandle', 'DWORD',[
			["PBLOB","pMem","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalMemoryStatus', 'VOID',[
			["PBLOB","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GlobalMemoryStatusEx', 'BOOL',[
			["PBLOB","lpBuffer","out"],
			])

		railgun.add_function( 'kernel32', 'GlobalReAlloc', 'DWORD',[
			["DWORD","hMem","in"],
			["DWORD","dwBytes","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalSize', 'DWORD',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalUnWire', 'BOOL',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalUnfix', 'VOID',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'GlobalUnlock', 'BOOL',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'HeapCompact', 'DWORD',[
			["DWORD","hHeap","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'HeapCreate', 'DWORD',[
			["DWORD","flOptions","in"],
			["DWORD","dwInitialSize","in"],
			["DWORD","dwMaximumSize","in"],
			])

		railgun.add_function( 'kernel32', 'HeapDestroy', 'BOOL',[
			["DWORD","hHeap","in"],
			])

		railgun.add_function( 'kernel32', 'HeapFree', 'BOOL',[
			["DWORD","hHeap","inout"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpMem","in"],
			])

		railgun.add_function( 'kernel32', 'HeapLock', 'BOOL',[
			["DWORD","hHeap","in"],
			])

		railgun.add_function( 'kernel32', 'HeapQueryInformation', 'BOOL',[
			["DWORD","HeapHandle","in"],
			["PDWORD","HeapInformationClass","in"],
			["PBLOB","HeapInformation","out"],
			["DWORD","HeapInformationLength","in"],
			["PDWORD","ReturnLength","out"],
			])

		railgun.add_function( 'kernel32', 'HeapSetInformation', 'BOOL',[
			["DWORD","HeapHandle","in"],
			["PDWORD","HeapInformationClass","in"],
			["PBLOB","HeapInformation","in"],
			["DWORD","HeapInformationLength","in"],
			])

		railgun.add_function( 'kernel32', 'HeapSize', 'DWORD',[
			["DWORD","hHeap","in"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpMem","in"],
			])

		railgun.add_function( 'kernel32', 'HeapUnlock', 'BOOL',[
			["DWORD","hHeap","in"],
			])

		railgun.add_function( 'kernel32', 'HeapValidate', 'BOOL',[
			["DWORD","hHeap","in"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpMem","in"],
			])

		railgun.add_function( 'kernel32', 'HeapWalk', 'BOOL',[
			["DWORD","hHeap","in"],
			["PBLOB","lpEntry","inout"],
			])

		railgun.add_function( 'kernel32', 'InitAtomTable', 'BOOL',[
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'InitializeCriticalSection', 'VOID',[
			["PBLOB","lpCriticalSection","out"],
			])

		railgun.add_function( 'kernel32', 'InitializeCriticalSectionAndSpinCount', 'BOOL',[
			["PBLOB","lpCriticalSection","out"],
			["DWORD","dwSpinCount","in"],
			])

		railgun.add_function( 'kernel32', 'InitializeSListHead', 'VOID',[
			["PBLOB","ListHead","inout"],
			])

		railgun.add_function( 'kernel32', 'InterlockedCompareExchange', 'DWORD',[
			["PDWORD","Destination","inout"],
			["DWORD","ExChange","in"],
			["DWORD","Comperand","in"],
			])

		railgun.add_function( 'kernel32', 'InterlockedDecrement', 'DWORD',[
			["PDWORD","lpAddend","inout"],
			])

		railgun.add_function( 'kernel32', 'InterlockedExchange', 'DWORD',[
			["PDWORD","Target","inout"],
			["DWORD","Value","in"],
			])

		railgun.add_function( 'kernel32', 'InterlockedExchangeAdd', 'DWORD',[
			["PDWORD","Addend","inout"],
			["DWORD","Value","in"],
			])

		railgun.add_function( 'kernel32', 'InterlockedIncrement', 'DWORD',[
			["PDWORD","lpAddend","inout"],
			])

		railgun.add_function( 'kernel32', 'IsBadCodePtr', 'BOOL',[
			["PBLOB","lpfn","in"],
			])

		railgun.add_function( 'kernel32', 'IsBadHugeReadPtr', 'BOOL',[
			["DWORD","ucb","in"],
			])

		railgun.add_function( 'kernel32', 'IsBadHugeWritePtr', 'BOOL',[
			["PBLOB","lp","in"],
			["DWORD","ucb","in"],
			])

		railgun.add_function( 'kernel32', 'IsBadReadPtr', 'BOOL',[
			["DWORD","ucb","in"],
			])

		railgun.add_function( 'kernel32', 'IsBadStringPtrA', 'BOOL',[
			["PCHAR","lpsz","in"],
			["DWORD","ucchMax","in"],
			])

		railgun.add_function( 'kernel32', 'IsBadStringPtrW', 'BOOL',[
			["PWCHAR","lpsz","in"],
			["DWORD","ucchMax","in"],
			])

		railgun.add_function( 'kernel32', 'IsBadWritePtr', 'BOOL',[
			["PBLOB","lp","in"],
			["DWORD","ucb","in"],
			])

		railgun.add_function( 'kernel32', 'IsDebuggerPresent', 'BOOL',[
			])

		railgun.add_function( 'kernel32', 'IsProcessInJob', 'BOOL',[
			["DWORD","ProcessHandle","in"],
			["DWORD","JobHandle","in"],
			["PBLOB","Result","out"],
			])

		railgun.add_function( 'kernel32', 'IsProcessorFeaturePresent', 'BOOL',[
			["DWORD","ProcessorFeature","in"],
			])

		railgun.add_function( 'kernel32', 'IsSystemResumeAutomatic', 'BOOL',[
			])

		railgun.add_function( 'kernel32', 'IsWow64Process', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","Wow64Process","out"],
			])

		railgun.add_function( 'kernel32', 'LeaveCriticalSection', 'VOID',[
			["PBLOB","lpCriticalSection","inout"],
			])

		railgun.add_function( 'kernel32', 'LoadLibraryA', 'DWORD',[
			["PCHAR","lpLibFileName","in"],
			])

		railgun.add_function( 'kernel32', 'LoadLibraryExA', 'DWORD',[
			["PCHAR","lpLibFileName","in"],
			["DWORD","hFile","inout"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'LoadLibraryExW', 'DWORD',[
			["PWCHAR","lpLibFileName","in"],
			["DWORD","hFile","inout"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'LoadLibraryW', 'DWORD',[
			["PWCHAR","lpLibFileName","in"],
			])

		railgun.add_function( 'kernel32', 'LoadModule', 'DWORD',[
			["PCHAR","lpModuleName","in"],
			["PBLOB","lpParameterBlock","in"],
			])

		railgun.add_function( 'kernel32', 'LoadResource', 'DWORD',[
			["DWORD","hModule","in"],
			["DWORD","hResInfo","in"],
			])

		railgun.add_function( 'kernel32', 'LocalAlloc', 'DWORD',[
			["DWORD","uFlags","in"],
			["DWORD","uBytes","in"],
			])

		railgun.add_function( 'kernel32', 'LocalCompact', 'DWORD',[
			["DWORD","uMinFree","in"],
			])

		railgun.add_function( 'kernel32', 'LocalFileTimeToFileTime', 'BOOL',[
			["PBLOB","lpLocalFileTime","in"],
			["PBLOB","lpFileTime","out"],
			])

		railgun.add_function( 'kernel32', 'LocalFlags', 'DWORD',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'LocalFree', 'DWORD',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'LocalHandle', 'DWORD',[
			["PBLOB","pMem","in"],
			])

		railgun.add_function( 'kernel32', 'LocalReAlloc', 'DWORD',[
			["DWORD","hMem","in"],
			["DWORD","uBytes","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'kernel32', 'LocalShrink', 'DWORD',[
			["DWORD","hMem","in"],
			["DWORD","cbNewSize","in"],
			])

		railgun.add_function( 'kernel32', 'LocalSize', 'DWORD',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'LocalUnlock', 'BOOL',[
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'kernel32', 'LockFile', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFileOffsetLow","in"],
			["DWORD","dwFileOffsetHigh","in"],
			["DWORD","nNumberOfBytesToLockLow","in"],
			["DWORD","nNumberOfBytesToLockHigh","in"],
			])

		railgun.add_function( 'kernel32', 'LockFileEx', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFlags","in"],
			["DWORD","dwReserved","inout"],
			["DWORD","nNumberOfBytesToLockLow","in"],
			["DWORD","nNumberOfBytesToLockHigh","in"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'MapUserPhysicalPages', 'BOOL',[
			["PBLOB","VirtualAddress","in"],
			["PDWORD","NumberOfPages","in"],
			["PBLOB","PageArray","in"],
			])

		railgun.add_function( 'kernel32', 'MapUserPhysicalPagesScatter', 'BOOL',[
			["PBLOB","VirtualAddresses","in"],
			["PDWORD","NumberOfPages","in"],
			["PBLOB","PageArray","in"],
			])

		railgun.add_function( 'kernel32', 'MoveFileA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			])

		railgun.add_function( 'kernel32', 'MoveFileExA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'MoveFileExW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'MoveFileW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			])

		railgun.add_function( 'kernel32', 'MoveFileWithProgressA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			["PBLOB","lpProgressRoutine","in"],
			["PBLOB","lpData","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'MoveFileWithProgressW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			["PBLOB","lpProgressRoutine","in"],
			["PBLOB","lpData","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'MulDiv', 'DWORD',[
			["DWORD","nNumber","in"],
			["DWORD","nNumerator","in"],
			["DWORD","nDenominator","in"],
			])

		railgun.add_function( 'kernel32', 'NeedCurrentDirectoryForExePathA', 'BOOL',[
			["PCHAR","ExeName","in"],
			])

		railgun.add_function( 'kernel32', 'NeedCurrentDirectoryForExePathW', 'BOOL',[
			["PWCHAR","ExeName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenEventA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenEventW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenFile', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["PBLOB","lpReOpenBuff","inout"],
			["DWORD","uStyle","in"],
			])

		railgun.add_function( 'kernel32', 'OpenFileMappingA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenFileMappingW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenJobObjectA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenJobObjectW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenMutexA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenMutexW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenProcess', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["DWORD","dwProcessId","in"],
			])

		railgun.add_function( 'kernel32', 'OpenSemaphoreA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenSemaphoreW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenThread', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["DWORD","dwThreadId","in"],
			])

		railgun.add_function( 'kernel32', 'OpenWaitableTimerA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpTimerName","in"],
			])

		railgun.add_function( 'kernel32', 'OpenWaitableTimerW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpTimerName","in"],
			])

		railgun.add_function( 'kernel32', 'OutputDebugStringA', 'VOID',[
			["PCHAR","lpOutputString","in"],
			])

		railgun.add_function( 'kernel32', 'OutputDebugStringW', 'VOID',[
			["PWCHAR","lpOutputString","in"],
			])

		railgun.add_function( 'kernel32', 'PeekNamedPipe', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nBufferSize","in"],
			["PDWORD","lpBytesRead","out"],
			["PDWORD","lpTotalBytesAvail","out"],
			["PDWORD","lpBytesLeftThisMessage","out"],
			])

		railgun.add_function( 'kernel32', 'PostQueuedCompletionStatus', 'BOOL',[
			["DWORD","CompletionPort","in"],
			["DWORD","dwNumberOfBytesTransferred","in"],
			["PDWORD","dwCompletionKey","in"],
			["PBLOB","lpOverlapped","in"],
			])

		railgun.add_function( 'kernel32', 'PrepareTape', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwOperation","in"],
			["BOOL","bImmediate","in"],
			])

		railgun.add_function( 'kernel32', 'ProcessIdToSessionId', 'BOOL',[
			["DWORD","dwProcessId","in"],
			["PDWORD","pSessionId","out"],
			])

		railgun.add_function( 'kernel32', 'PulseEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])

		railgun.add_function( 'kernel32', 'PurgeComm', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'QueryActCtxW', 'BOOL',[
			["DWORD","dwFlags","in"],
			["DWORD","hActCtx","in"],
			["PBLOB","pvSubInstance","in"],
			["DWORD","ulInfoClass","in"],
			["PBLOB","pvBuffer","out"],
			["DWORD","cbBuffer","in"],
			["PDWORD","pcbWrittenOrRequired","out"],
			])

		railgun.add_function( 'kernel32', 'QueryDepthSList', 'WORD',[
			["PBLOB","ListHead","in"],
			])

		railgun.add_function( 'kernel32', 'QueryDosDeviceA', 'DWORD',[
			["PCHAR","lpDeviceName","in"],
			["PCHAR","lpTargetPath","out"],
			["DWORD","ucchMax","in"],
			])

		railgun.add_function( 'kernel32', 'QueryDosDeviceW', 'DWORD',[
			["PWCHAR","lpDeviceName","in"],
			["PWCHAR","lpTargetPath","out"],
			["DWORD","ucchMax","in"],
			])

		railgun.add_function( 'kernel32', 'QueryInformationJobObject', 'BOOL',[
			["DWORD","hJob","in"],
			["PBLOB","JobObjectInformationClass","in"],
			["PBLOB","lpJobObjectInformation","out"],
			["DWORD","cbJobObjectInformationLength","in"],
			["PDWORD","lpReturnLength","out"],
			])

		railgun.add_function( 'kernel32', 'QueryMemoryResourceNotification', 'BOOL',[
			["DWORD","ResourceNotificationHandle","in"],
			["PBLOB","ResourceState","out"],
			])

		railgun.add_function( 'kernel32', 'QueryPerformanceCounter', 'BOOL',[
			["PBLOB","lpPerformanceCount","out"],
			])

		railgun.add_function( 'kernel32', 'QueryPerformanceFrequency', 'BOOL',[
			["PBLOB","lpFrequency","out"],
			])

		railgun.add_function( 'kernel32', 'QueueUserAPC', 'DWORD',[
			["PBLOB","pfnAPC","in"],
			["DWORD","hThread","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'kernel32', 'QueueUserWorkItem', 'BOOL',[
			["PBLOB","Function","in"],
			["PBLOB","Context","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'kernel32', 'RaiseException', 'VOID',[
			["DWORD","dwExceptionCode","in"],
			["DWORD","dwExceptionFlags","in"],
			["DWORD","nNumberOfArguments","in"],
			["PBLOB","lpArguments","in"],
			])

		railgun.add_function( 'kernel32', 'ReOpenFile', 'DWORD',[
			["DWORD","hOriginalFile","in"],
			["DWORD","dwDesiredAccess","in"],
			["DWORD","dwShareMode","in"],
			["DWORD","dwFlagsAndAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'ReadDirectoryChangesW', 'BOOL',[
			["DWORD","hDirectory","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nBufferLength","in"],
			["BOOL","bWatchSubtree","in"],
			["DWORD","dwNotifyFilter","in"],
			["PDWORD","lpBytesReturned","out"],
			["PBLOB","lpOverlapped","inout"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'kernel32', 'ReadFile', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PDWORD","lpNumberOfBytesRead","out"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'ReadFileEx', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PBLOB","lpOverlapped","inout"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'kernel32', 'ReadFileScatter', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","aSegmentArray[]","in"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PDWORD","lpReserved","inout"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'ReadProcessMemory', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpBaseAddress","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nSize","in"],
			["PDWORD","lpNumberOfBytesRead","out"],
			])

		railgun.add_function( 'kernel32', 'RegisterWaitForSingleObject', 'BOOL',[
			["PDWORD","phNewWaitObject","out"],
			["DWORD","hObject","in"],
			["PBLOB","Callback","in"],
			["PBLOB","Context","in"],
			["DWORD","dwMilliseconds","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'RegisterWaitForSingleObjectEx', 'DWORD',[
			["DWORD","hObject","in"],
			["PBLOB","Callback","in"],
			["PBLOB","Context","in"],
			["DWORD","dwMilliseconds","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'ReleaseActCtx', 'VOID',[
			["DWORD","hActCtx","inout"],
			])

		railgun.add_function( 'kernel32', 'ReleaseMutex', 'BOOL',[
			["DWORD","hMutex","in"],
			])

		railgun.add_function( 'kernel32', 'ReleaseSemaphore', 'BOOL',[
			["DWORD","hSemaphore","in"],
			["DWORD","lReleaseCount","in"],
			["PBLOB","lpPreviousCount","out"],
			])

		railgun.add_function( 'kernel32', 'RemoveDirectoryA', 'BOOL',[
			["PCHAR","lpPathName","in"],
			])

		railgun.add_function( 'kernel32', 'RemoveDirectoryW', 'BOOL',[
			["PWCHAR","lpPathName","in"],
			])

		railgun.add_function( 'kernel32', 'RemoveVectoredContinueHandler', 'DWORD',[
			["PBLOB","Handle","in"],
			])

		railgun.add_function( 'kernel32', 'RemoveVectoredExceptionHandler', 'DWORD',[
			["PBLOB","Handle","in"],
			])

		railgun.add_function( 'kernel32', 'ReplaceFileA', 'BOOL',[
			["PCHAR","lpReplacedFileName","in"],
			["PCHAR","lpReplacementFileName","in"],
			["PCHAR","lpBackupFileName","in"],
			["DWORD","dwReplaceFlags","in"],
			["PBLOB","lpExclude","inout"],
			["PBLOB","lpReserved","inout"],
			])

		railgun.add_function( 'kernel32', 'ReplaceFileW', 'BOOL',[
			["PWCHAR","lpReplacedFileName","in"],
			["PWCHAR","lpReplacementFileName","in"],
			["PWCHAR","lpBackupFileName","in"],
			["DWORD","dwReplaceFlags","in"],
			["PBLOB","lpExclude","inout"],
			["PBLOB","lpReserved","inout"],
			])

		railgun.add_function( 'kernel32', 'RequestDeviceWakeup', 'BOOL',[
			["DWORD","hDevice","in"],
			])

		railgun.add_function( 'kernel32', 'RequestWakeupLatency', 'BOOL',[
			["PBLOB","latency","in"],
			])

		railgun.add_function( 'kernel32', 'ResetEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])

		railgun.add_function( 'kernel32', 'ResetWriteWatch', 'DWORD',[
			["PBLOB","lpBaseAddress","in"],
			["DWORD","dwRegionSize","in"],
			])

		railgun.add_function( 'kernel32', 'RestoreLastError', 'VOID',[
			["DWORD","dwErrCode","in"],
			])

		railgun.add_function( 'kernel32', 'ResumeThread', 'DWORD',[
			["DWORD","hThread","in"],
			])

		railgun.add_function( 'kernel32', 'SearchPathA', 'DWORD',[
			["PCHAR","lpPath","in"],
			["PCHAR","lpFileName","in"],
			["PCHAR","lpExtension","in"],
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			["PBLOB","lpFilePart","out"],
			])

		railgun.add_function( 'kernel32', 'SearchPathW', 'DWORD',[
			["PWCHAR","lpPath","in"],
			["PWCHAR","lpFileName","in"],
			["PWCHAR","lpExtension","in"],
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			["PBLOB","lpFilePart","out"],
			])

		railgun.add_function( 'kernel32', 'SetCommBreak', 'BOOL',[
			["DWORD","hFile","in"],
			])

		railgun.add_function( 'kernel32', 'SetCommConfig', 'BOOL',[
			["DWORD","hCommDev","in"],
			["PBLOB","lpCC","in"],
			["DWORD","dwSize","in"],
			])

		railgun.add_function( 'kernel32', 'SetCommMask', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwEvtMask","in"],
			])

		railgun.add_function( 'kernel32', 'SetCommState', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpDCB","in"],
			])

		railgun.add_function( 'kernel32', 'SetCommTimeouts', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCommTimeouts","in"],
			])

		railgun.add_function( 'kernel32', 'SetComputerNameA', 'BOOL',[
			["PCHAR","lpComputerName","in"],
			])

		railgun.add_function( 'kernel32', 'SetComputerNameExA', 'BOOL',[
			["DWORD","NameType","in"],
			["PCHAR","lpBuffer","in"],
			])

		railgun.add_function( 'kernel32', 'SetComputerNameExW', 'BOOL',[
			["DWORD","NameType","in"],
			["PWCHAR","lpBuffer","in"],
			])

		railgun.add_function( 'kernel32', 'SetComputerNameW', 'BOOL',[
			["PWCHAR","lpComputerName","in"],
			])

		railgun.add_function( 'kernel32', 'SetCriticalSectionSpinCount', 'DWORD',[
			["PBLOB","lpCriticalSection","inout"],
			["DWORD","dwSpinCount","in"],
			])

		railgun.add_function( 'kernel32', 'SetCurrentDirectoryA', 'BOOL',[
			["PCHAR","lpPathName","in"],
			])

		railgun.add_function( 'kernel32', 'SetCurrentDirectoryW', 'BOOL',[
			["PWCHAR","lpPathName","in"],
			])

		railgun.add_function( 'kernel32', 'SetDefaultCommConfigA', 'BOOL',[
			["PCHAR","lpszName","in"],
			["PBLOB","lpCC","in"],
			["DWORD","dwSize","in"],
			])

		railgun.add_function( 'kernel32', 'SetDefaultCommConfigW', 'BOOL',[
			["PWCHAR","lpszName","in"],
			["PBLOB","lpCC","in"],
			["DWORD","dwSize","in"],
			])

		railgun.add_function( 'kernel32', 'SetDllDirectoryA', 'BOOL',[
			["PCHAR","lpPathName","in"],
			])

		railgun.add_function( 'kernel32', 'SetDllDirectoryW', 'BOOL',[
			["PWCHAR","lpPathName","in"],
			])

		railgun.add_function( 'kernel32', 'SetEndOfFile', 'BOOL',[
			["DWORD","hFile","in"],
			])

		railgun.add_function( 'kernel32', 'SetEnvironmentStringsA', 'BOOL',[
			["PBLOB","NewEnvironment","in"],
			])

		railgun.add_function( 'kernel32', 'SetEnvironmentStringsW', 'BOOL',[
			["PBLOB","NewEnvironment","in"],
			])

		railgun.add_function( 'kernel32', 'SetEnvironmentVariableA', 'BOOL',[
			["PCHAR","lpName","in"],
			["PCHAR","lpValue","in"],
			])

		railgun.add_function( 'kernel32', 'SetEnvironmentVariableW', 'BOOL',[
			["PWCHAR","lpName","in"],
			["PWCHAR","lpValue","in"],
			])

		railgun.add_function( 'kernel32', 'SetErrorMode', 'DWORD',[
			["DWORD","uMode","in"],
			])

		railgun.add_function( 'kernel32', 'SetEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])

		railgun.add_function( 'kernel32', 'SetFileApisToANSI', 'VOID',[
			])

		railgun.add_function( 'kernel32', 'SetFileApisToOEM', 'VOID',[
			])

		railgun.add_function( 'kernel32', 'SetFileAttributesA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["DWORD","dwFileAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'SetFileAttributesW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["DWORD","dwFileAttributes","in"],
			])

		railgun.add_function( 'kernel32', 'SetFilePointer', 'DWORD',[
			["DWORD","hFile","in"],
			["DWORD","lDistanceToMove","in"],
			["PDWORD","lpDistanceToMoveHigh","in"],
			["DWORD","dwMoveMethod","in"],
			])

		railgun.add_function( 'kernel32', 'SetFilePointerEx', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","liDistanceToMove","in"],
			["PBLOB","lpNewFilePointer","out"],
			["DWORD","dwMoveMethod","in"],
			])

		railgun.add_function( 'kernel32', 'SetFileShortNameA', 'BOOL',[
			["DWORD","hFile","in"],
			["PCHAR","lpShortName","in"],
			])

		railgun.add_function( 'kernel32', 'SetFileShortNameW', 'BOOL',[
			["DWORD","hFile","in"],
			["PWCHAR","lpShortName","in"],
			])

		railgun.add_function( 'kernel32', 'SetFileTime', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCreationTime","in"],
			["PBLOB","lpLastAccessTime","in"],
			["PBLOB","lpLastWriteTime","in"],
			])

		railgun.add_function( 'kernel32', 'SetFileValidData', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","ValidDataLength","in"],
			])

		railgun.add_function( 'kernel32', 'SetFirmwareEnvironmentVariableA', 'BOOL',[
			["PCHAR","lpName","in"],
			["PCHAR","lpGuid","in"],
			["PBLOB","pValue","in"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'SetFirmwareEnvironmentVariableW', 'BOOL',[
			["PWCHAR","lpName","in"],
			["PWCHAR","lpGuid","in"],
			["PBLOB","pValue","in"],
			["DWORD","nSize","in"],
			])

		railgun.add_function( 'kernel32', 'SetHandleCount', 'DWORD',[
			["DWORD","uNumber","in"],
			])

		railgun.add_function( 'kernel32', 'SetHandleInformation', 'BOOL',[
			["DWORD","hObject","in"],
			["DWORD","dwMask","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'SetInformationJobObject', 'BOOL',[
			["DWORD","hJob","in"],
			["PBLOB","JobObjectInformationClass","in"],
			["PBLOB","lpJobObjectInformation","in"],
			["DWORD","cbJobObjectInformationLength","in"],
			])

		railgun.add_function( 'kernel32', 'SetLastError', 'VOID',[
			["DWORD","dwErrCode","in"],
			])

		railgun.add_function( 'kernel32', 'SetLocalTime', 'BOOL',[
			["PBLOB","lpSystemTime","in"],
			])

		railgun.add_function( 'kernel32', 'SetMailslotInfo', 'BOOL',[
			["DWORD","hMailslot","in"],
			["DWORD","lReadTimeout","in"],
			])

		railgun.add_function( 'kernel32', 'SetMessageWaitingIndicator', 'BOOL',[
			["DWORD","hMsgIndicator","in"],
			["DWORD","ulMsgCount","in"],
			])

		railgun.add_function( 'kernel32', 'SetNamedPipeHandleState', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PDWORD","lpMode","in"],
			["PDWORD","lpMaxCollectionCount","in"],
			["PDWORD","lpCollectDataTimeout","in"],
			])

		railgun.add_function( 'kernel32', 'SetPriorityClass', 'BOOL',[
			["DWORD","hProcess","in"],
			["DWORD","dwPriorityClass","in"],
			])

		railgun.add_function( 'kernel32', 'SetProcessAffinityMask', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","dwProcessAffinityMask","in"],
			])

		railgun.add_function( 'kernel32', 'SetProcessPriorityBoost', 'BOOL',[
			["DWORD","hProcess","in"],
			["BOOL","bDisablePriorityBoost","in"],
			])

		railgun.add_function( 'kernel32', 'SetProcessShutdownParameters', 'BOOL',[
			["DWORD","dwLevel","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'kernel32', 'SetProcessWorkingSetSize', 'BOOL',[
			["DWORD","hProcess","in"],
			["DWORD","dwMinimumWorkingSetSize","in"],
			["DWORD","dwMaximumWorkingSetSize","in"],
			])

		railgun.add_function( 'kernel32', 'SetProcessWorkingSetSizeEx', 'BOOL',[
			["DWORD","hProcess","in"],
			["DWORD","dwMinimumWorkingSetSize","in"],
			["DWORD","dwMaximumWorkingSetSize","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'kernel32', 'SetStdHandle', 'BOOL',[
			["DWORD","nStdHandle","in"],
			["DWORD","hHandle","in"],
			])

		railgun.add_function( 'kernel32', 'SetSystemFileCacheSize', 'BOOL',[
			["DWORD","MinimumFileCacheSize","in"],
			["DWORD","MaximumFileCacheSize","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'kernel32', 'SetSystemPowerState', 'BOOL',[
			["BOOL","fSuspend","in"],
			["BOOL","fForce","in"],
			])

		railgun.add_function( 'kernel32', 'SetSystemTime', 'BOOL',[
			["PBLOB","lpSystemTime","in"],
			])

		railgun.add_function( 'kernel32', 'SetSystemTimeAdjustment', 'BOOL',[
			["DWORD","dwTimeAdjustment","in"],
			["BOOL","bTimeAdjustmentDisabled","in"],
			])

		railgun.add_function( 'kernel32', 'SetTapeParameters', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwOperation","in"],
			["PBLOB","lpTapeInformation","in"],
			])

		railgun.add_function( 'kernel32', 'SetTapePosition', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwPositionMethod","in"],
			["DWORD","dwPartition","in"],
			["DWORD","dwOffsetLow","in"],
			["DWORD","dwOffsetHigh","in"],
			["BOOL","bImmediate","in"],
			])

		railgun.add_function( 'kernel32', 'SetThreadContext', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","lpContext","in"],
			])

		railgun.add_function( 'kernel32', 'SetThreadExecutionState', 'DWORD',[
			["DWORD","esFlags","in"],
			])

		railgun.add_function( 'kernel32', 'SetThreadIdealProcessor', 'DWORD',[
			["DWORD","hThread","in"],
			["DWORD","dwIdealProcessor","in"],
			])

		railgun.add_function( 'kernel32', 'SetThreadPriority', 'BOOL',[
			["DWORD","hThread","in"],
			["DWORD","nPriority","in"],
			])

		railgun.add_function( 'kernel32', 'SetThreadPriorityBoost', 'BOOL',[
			["DWORD","hThread","in"],
			["BOOL","bDisablePriorityBoost","in"],
			])

		railgun.add_function( 'kernel32', 'SetThreadStackGuarantee', 'BOOL',[
			["PDWORD","StackSizeInBytes","inout"],
			])

		railgun.add_function( 'kernel32', 'SetTimeZoneInformation', 'BOOL',[
			["PBLOB","lpTimeZoneInformation","in"],
			])

		railgun.add_function( 'kernel32', 'SetTimerQueueTimer', 'DWORD',[
			["DWORD","TimerQueue","in"],
			["PBLOB","Callback","in"],
			["PBLOB","Parameter","in"],
			["DWORD","DueTime","in"],
			["DWORD","Period","in"],
			["BOOL","PreferIo","in"],
			])

		railgun.add_function( 'kernel32', 'SetVolumeLabelA', 'BOOL',[
			["PCHAR","lpRootPathName","in"],
			["PCHAR","lpVolumeName","in"],
			])

		railgun.add_function( 'kernel32', 'SetVolumeLabelW', 'BOOL',[
			["PWCHAR","lpRootPathName","in"],
			["PWCHAR","lpVolumeName","in"],
			])

		railgun.add_function( 'kernel32', 'SetVolumeMountPointA', 'BOOL',[
			["PCHAR","lpszVolumeMountPoint","in"],
			["PCHAR","lpszVolumeName","in"],
			])

		railgun.add_function( 'kernel32', 'SetVolumeMountPointW', 'BOOL',[
			["PWCHAR","lpszVolumeMountPoint","in"],
			["PWCHAR","lpszVolumeName","in"],
			])

		railgun.add_function( 'kernel32', 'SetWaitableTimer', 'BOOL',[
			["DWORD","hTimer","in"],
			["PBLOB","lpDueTime","in"],
			["DWORD","lPeriod","in"],
			["PBLOB","pfnCompletionRoutine","in"],
			["PBLOB","lpArgToCompletionRoutine","in"],
			["BOOL","fResume","in"],
			])

		railgun.add_function( 'kernel32', 'SetupComm', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwInQueue","in"],
			["DWORD","dwOutQueue","in"],
			])

		railgun.add_function( 'kernel32', 'SignalObjectAndWait', 'DWORD',[
			["DWORD","hObjectToSignal","in"],
			["DWORD","hObjectToWaitOn","in"],
			["DWORD","dwMilliseconds","in"],
			["BOOL","bAlertable","in"],
			])

		railgun.add_function( 'kernel32', 'SizeofResource', 'DWORD',[
			["DWORD","hModule","in"],
			["DWORD","hResInfo","in"],
			])

		railgun.add_function( 'kernel32', 'Sleep', 'VOID',[
			["DWORD","dwMilliseconds","in"],
			])

		railgun.add_function( 'kernel32', 'SleepEx', 'DWORD',[
			["DWORD","dwMilliseconds","in"],
			["BOOL","bAlertable","in"],
			])

		railgun.add_function( 'kernel32', 'SuspendThread', 'DWORD',[
			["DWORD","hThread","in"],
			])

		railgun.add_function( 'kernel32', 'SwitchToFiber', 'VOID',[
			["PBLOB","lpFiber","in"],
			])

		railgun.add_function( 'kernel32', 'SwitchToThread', 'BOOL',[
			])

		railgun.add_function( 'kernel32', 'SystemTimeToFileTime', 'BOOL',[
			["PBLOB","lpSystemTime","in"],
			["PBLOB","lpFileTime","out"],
			])

		railgun.add_function( 'kernel32', 'SystemTimeToTzSpecificLocalTime', 'BOOL',[
			["PBLOB","lpTimeZoneInformation","in"],
			["PBLOB","lpUniversalTime","in"],
			["PBLOB","lpLocalTime","out"],
			])

		railgun.add_function( 'kernel32', 'TerminateJobObject', 'BOOL',[
			["DWORD","hJob","in"],
			["DWORD","uExitCode","in"],
			])

		railgun.add_function( 'kernel32', 'TerminateProcess', 'BOOL',[
			["DWORD","hProcess","in"],
			["DWORD","uExitCode","in"],
			])

		railgun.add_function( 'kernel32', 'TerminateThread', 'BOOL',[
			["DWORD","hThread","in"],
			["DWORD","dwExitCode","in"],
			])

		railgun.add_function( 'kernel32', 'TlsAlloc', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'TlsFree', 'BOOL',[
			["DWORD","dwTlsIndex","in"],
			])

		railgun.add_function( 'kernel32', 'TlsSetValue', 'BOOL',[
			["DWORD","dwTlsIndex","in"],
			["PBLOB","lpTlsValue","in"],
			])

		railgun.add_function( 'kernel32', 'TransactNamedPipe', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PBLOB","lpInBuffer","in"],
			["DWORD","nInBufferSize","in"],
			["PBLOB","lpOutBuffer","out"],
			["DWORD","nOutBufferSize","in"],
			["PDWORD","lpBytesRead","out"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'TransmitCommChar', 'BOOL',[
			["DWORD","hFile","in"],
			["BYTE","cChar","in"],
			])

		railgun.add_function( 'kernel32', 'TryEnterCriticalSection', 'BOOL',[
			["PBLOB","lpCriticalSection","inout"],
			])

		railgun.add_function( 'kernel32', 'TzSpecificLocalTimeToSystemTime', 'BOOL',[
			["PBLOB","lpTimeZoneInformation","in"],
			["PBLOB","lpLocalTime","in"],
			["PBLOB","lpUniversalTime","out"],
			])

		railgun.add_function( 'kernel32', 'UnhandledExceptionFilter', 'DWORD',[
			["PBLOB","ExceptionInfo","in"],
			])

		railgun.add_function( 'kernel32', 'UnlockFile', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFileOffsetLow","in"],
			["DWORD","dwFileOffsetHigh","in"],
			["DWORD","nNumberOfBytesToUnlockLow","in"],
			["DWORD","nNumberOfBytesToUnlockHigh","in"],
			])

		railgun.add_function( 'kernel32', 'UnlockFileEx', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwReserved","inout"],
			["DWORD","nNumberOfBytesToUnlockLow","in"],
			["DWORD","nNumberOfBytesToUnlockHigh","in"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'UnmapViewOfFile', 'BOOL',[
			["PBLOB","lpBaseAddress","in"],
			])

		railgun.add_function( 'kernel32', 'UnregisterWait', 'BOOL',[
			["DWORD","WaitHandle","in"],
			])

		railgun.add_function( 'kernel32', 'UnregisterWaitEx', 'BOOL',[
			["DWORD","WaitHandle","in"],
			["DWORD","CompletionEvent","in"],
			])

		railgun.add_function( 'kernel32', 'UpdateResourceA', 'BOOL',[
			["DWORD","hUpdate","in"],
			["PCHAR","lpType","in"],
			["PCHAR","lpName","in"],
			["WORD","wLanguage","in"],
			["PBLOB","lpData","in"],
			["DWORD","cb","in"],
			])

		railgun.add_function( 'kernel32', 'UpdateResourceW', 'BOOL',[
			["DWORD","hUpdate","in"],
			["PWCHAR","lpType","in"],
			["PWCHAR","lpName","in"],
			["WORD","wLanguage","in"],
			["PBLOB","lpData","in"],
			["DWORD","cb","in"],
			])

		railgun.add_function( 'kernel32', 'VerifyVersionInfoA', 'BOOL',[
			["PBLOB","lpVersionInformation","inout"],
			["DWORD","dwTypeMask","in"],
			["PBLOB","dwlConditionMask","in"],
			])

		railgun.add_function( 'kernel32', 'VerifyVersionInfoW', 'BOOL',[
			["PBLOB","lpVersionInformation","inout"],
			["DWORD","dwTypeMask","in"],
			["PBLOB","dwlConditionMask","in"],
			])

		railgun.add_function( 'kernel32', 'VirtualFree', 'BOOL',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","dwFreeType","in"],
			])

		railgun.add_function( 'kernel32', 'VirtualFreeEx', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","dwFreeType","in"],
			])

		railgun.add_function( 'kernel32', 'VirtualLock', 'BOOL',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			])

		railgun.add_function( 'kernel32', 'VirtualProtect', 'BOOL',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","flNewProtect","in"],
			["PDWORD","lpflOldProtect","out"],
			])

		railgun.add_function( 'kernel32', 'VirtualProtectEx', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","flNewProtect","in"],
			["PDWORD","lpflOldProtect","out"],
			])

		railgun.add_function( 'kernel32', 'VirtualQuery', 'DWORD',[
			["PBLOB","lpAddress","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","dwLength","in"],
			])

		railgun.add_function( 'kernel32', 'VirtualQueryEx', 'DWORD',[
			["DWORD","hProcess","in"],
			["PBLOB","lpAddress","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","dwLength","in"],
			])

		railgun.add_function( 'kernel32', 'VirtualUnlock', 'BOOL',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			])

		railgun.add_function( 'kernel32', 'WTSGetActiveConsoleSessionId', 'DWORD',[
			])

		railgun.add_function( 'kernel32', 'WaitCommEvent', 'BOOL',[
			["DWORD","hFile","in"],
			["PDWORD","lpEvtMask","inout"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'WaitForDebugEvent', 'BOOL',[
			["PBLOB","lpDebugEvent","in"],
			["DWORD","dwMilliseconds","in"],
			])

		railgun.add_function( 'kernel32', 'WaitForMultipleObjects', 'DWORD',[
			["DWORD","nCount","in"],
			["PDWORD","lpHandles","in"],
			["BOOL","bWaitAll","in"],
			["DWORD","dwMilliseconds","in"],
			])

		railgun.add_function( 'kernel32', 'WaitForMultipleObjectsEx', 'DWORD',[
			["DWORD","nCount","in"],
			["PDWORD","lpHandles","in"],
			["BOOL","bWaitAll","in"],
			["DWORD","dwMilliseconds","in"],
			["BOOL","bAlertable","in"],
			])

		railgun.add_function( 'kernel32', 'WaitForSingleObject', 'DWORD',[
			["DWORD","hHandle","in"],
			["DWORD","dwMilliseconds","in"],
			])

		railgun.add_function( 'kernel32', 'WaitForSingleObjectEx', 'DWORD',[
			["DWORD","hHandle","in"],
			["DWORD","dwMilliseconds","in"],
			["BOOL","bAlertable","in"],
			])

		railgun.add_function( 'kernel32', 'WaitNamedPipeA', 'BOOL',[
			["PCHAR","lpNamedPipeName","in"],
			["DWORD","nTimeOut","in"],
			])

		railgun.add_function( 'kernel32', 'WaitNamedPipeW', 'BOOL',[
			["PWCHAR","lpNamedPipeName","in"],
			["DWORD","nTimeOut","in"],
			])

		railgun.add_function( 'kernel32', 'WinExec', 'DWORD',[
			["PCHAR","lpCmdLine","in"],
			["DWORD","uCmdShow","in"],
			])

		railgun.add_function( 'kernel32', 'Wow64DisableWow64FsRedirection', 'BOOL',[
			["PBLOB","OldValue","out"],
			])

		railgun.add_function( 'kernel32', 'Wow64EnableWow64FsRedirection', 'BOOL',[
			["BOOL","Wow64FsEnableRedirection","in"],
			])

		railgun.add_function( 'kernel32', 'Wow64RevertWow64FsRedirection', 'BOOL',[
			["PBLOB","OlValue","in"],
			])

		railgun.add_function( 'kernel32', 'WriteFile', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","nNumberOfBytesToWrite","in"],
			["PDWORD","lpNumberOfBytesWritten","out"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'WriteFileEx', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","nNumberOfBytesToWrite","in"],
			["PBLOB","lpOverlapped","inout"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'kernel32', 'WriteFileGather', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","aSegmentArray[]","in"],
			["DWORD","nNumberOfBytesToWrite","in"],
			["PDWORD","lpReserved","inout"],
			["PBLOB","lpOverlapped","inout"],
			])

		railgun.add_function( 'kernel32', 'WritePrivateProfileSectionA', 'BOOL',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpString","in"],
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'WritePrivateProfileSectionW', 'BOOL',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpString","in"],
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'WritePrivateProfileStringA', 'BOOL',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["PCHAR","lpString","in"],
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'WritePrivateProfileStringW', 'BOOL',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["PWCHAR","lpString","in"],
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'kernel32', 'WritePrivateProfileStructA', 'BOOL',[
			["PCHAR","lpszSection","in"],
			["PCHAR","lpszKey","in"],
			["PBLOB","lpStruct","in"],
			["DWORD","uSizeStruct","in"],
			["PCHAR","szFile","in"],
			])

		railgun.add_function( 'kernel32', 'WritePrivateProfileStructW', 'BOOL',[
			["PWCHAR","lpszSection","in"],
			["PWCHAR","lpszKey","in"],
			["PBLOB","lpStruct","in"],
			["DWORD","uSizeStruct","in"],
			["PWCHAR","szFile","in"],
			])

		railgun.add_function( 'kernel32', 'WriteProcessMemory', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpBaseAddress","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","nSize","in"],
			["PDWORD","lpNumberOfBytesWritten","out"],
			])

		railgun.add_function( 'kernel32', 'WriteProfileSectionA', 'BOOL',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'WriteProfileSectionW', 'BOOL',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'WriteProfileStringA', 'BOOL',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'WriteProfileStringW', 'BOOL',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'WriteTapemark', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwTapemarkType","in"],
			["DWORD","dwTapemarkCount","in"],
			["BOOL","bImmediate","in"],
			])

		railgun.add_function( 'kernel32', 'ZombifyActCtx', 'BOOL',[
			["DWORD","hActCtx","inout"],
			])

		railgun.add_function( 'kernel32', '_hread', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","lBytes","in"],
			])

		railgun.add_function( 'kernel32', '_hwrite', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","lBytes","in"],
			])

		railgun.add_function( 'kernel32', '_lclose', 'DWORD',[
			["DWORD","hFile","in"],
			])

		railgun.add_function( 'kernel32', '_lcreat', 'DWORD',[
			["PCHAR","lpPathName","in"],
			["DWORD","iAttribute","in"],
			])

		railgun.add_function( 'kernel32', '_llseek', 'DWORD',[
			["DWORD","hFile","in"],
			["DWORD","lOffset","in"],
			["DWORD","iOrigin","in"],
			])

		railgun.add_function( 'kernel32', '_lopen', 'DWORD',[
			["PCHAR","lpPathName","in"],
			["DWORD","iReadWrite","in"],
			])

		railgun.add_function( 'kernel32', '_lread', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","uBytes","in"],
			])

		railgun.add_function( 'kernel32', '_lwrite', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","uBytes","in"],
			])

		railgun.add_function( 'kernel32', 'lstrcmpA', 'DWORD',[
			["PCHAR","lpString1","in"],
			["PCHAR","lpString2","in"],
			])

		railgun.add_function( 'kernel32', 'lstrcmpW', 'DWORD',[
			["PWCHAR","lpString1","in"],
			["PWCHAR","lpString2","in"],
			])

		railgun.add_function( 'kernel32', 'lstrcmpiA', 'DWORD',[
			["PCHAR","lpString1","in"],
			["PCHAR","lpString2","in"],
			])

		railgun.add_function( 'kernel32', 'lstrcmpiW', 'DWORD',[
			["PWCHAR","lpString1","in"],
			["PWCHAR","lpString2","in"],
			])

		railgun.add_function( 'kernel32', 'lstrlenA', 'DWORD',[
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'kernel32', 'lstrlenW', 'DWORD',[
			["PWCHAR","lpString","in"],
			])


		railgun.add_dll('user32','user32')
		railgun.add_function( 'user32', 'ActivateKeyboardLayout', 'DWORD',[
			["DWORD","hkl","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'AdjustWindowRect', 'BOOL',[
			["PBLOB","lpRect","inout"],
			["DWORD","dwStyle","in"],
			["BOOL","bMenu","in"],
			])

		railgun.add_function( 'user32', 'AdjustWindowRectEx', 'BOOL',[
			["PBLOB","lpRect","inout"],
			["DWORD","dwStyle","in"],
			["BOOL","bMenu","in"],
			["DWORD","dwExStyle","in"],
			])

		railgun.add_function( 'user32', 'AllowSetForegroundWindow', 'BOOL',[
			["DWORD","dwProcessId","in"],
			])

		railgun.add_function( 'user32', 'AnimateWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","dwTime","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'AnyPopup', 'BOOL',[
			])

		railgun.add_function( 'user32', 'AppendMenuA', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'AppendMenuW', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PWCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'ArrangeIconicWindows', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'AttachThreadInput', 'BOOL',[
			["DWORD","idAttach","in"],
			["DWORD","idAttachTo","in"],
			["BOOL","fAttach","in"],
			])

		railgun.add_function( 'user32', 'BeginDeferWindowPos', 'DWORD',[
			["DWORD","nNumWindows","in"],
			])

		railgun.add_function( 'user32', 'BeginPaint', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpPaint","out"],
			])

		railgun.add_function( 'user32', 'BringWindowToTop', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessage', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessageA', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessageExA', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["PBLOB","pbsmInfo","out"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessageExW', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["PBLOB","pbsmInfo","out"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessageW', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CallMsgFilterA', 'BOOL',[
			["PBLOB","lpMsg","in"],
			["DWORD","nCode","in"],
			])

		railgun.add_function( 'user32', 'CallMsgFilterW', 'BOOL',[
			["PBLOB","lpMsg","in"],
			["DWORD","nCode","in"],
			])

		railgun.add_function( 'user32', 'CallNextHookEx', 'DWORD',[
			["DWORD","hhk","in"],
			["DWORD","nCode","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CallWindowProcA', 'DWORD',[
			["PBLOB","lpPrevWndFunc","in"],
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CallWindowProcW', 'DWORD',[
			["PBLOB","lpPrevWndFunc","in"],
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CascadeWindows', 'WORD',[
			["DWORD","hwndParent","in"],
			["DWORD","wHow","in"],
			["PBLOB","lpRect","in"],
			["DWORD","cKids","in"],
			["PDWORD","lpKids","in"],
			])

		railgun.add_function( 'user32', 'ChangeClipboardChain', 'BOOL',[
			["DWORD","hWndRemove","in"],
			["DWORD","hWndNewNext","in"],
			])

		railgun.add_function( 'user32', 'ChangeDisplaySettingsA', 'DWORD',[
			["PBLOB","lpDevMode","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'ChangeDisplaySettingsExA', 'DWORD',[
			["PCHAR","lpszDeviceName","in"],
			["PBLOB","lpDevMode","in"],
			["DWORD","hwnd","inout"],
			["DWORD","dwflags","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'user32', 'ChangeDisplaySettingsExW', 'DWORD',[
			["PWCHAR","lpszDeviceName","in"],
			["PBLOB","lpDevMode","in"],
			["DWORD","hwnd","inout"],
			["DWORD","dwflags","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'user32', 'ChangeDisplaySettingsW', 'DWORD',[
			["PBLOB","lpDevMode","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'ChangeMenuA', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","cmd","in"],
			["PCHAR","lpszNewItem","in"],
			["DWORD","cmdInsert","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'ChangeMenuW', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","cmd","in"],
			["PWCHAR","lpszNewItem","in"],
			["DWORD","cmdInsert","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'CharLowerBuffA', 'DWORD',[
			["PCHAR","lpsz","in"],
			["DWORD","cchLength","in"],
			])

		railgun.add_function( 'user32', 'CharLowerBuffW', 'DWORD',[
			["PWCHAR","lpsz","in"],
			["DWORD","cchLength","in"],
			])

		railgun.add_function( 'user32', 'CharToOemA', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			])

		railgun.add_function( 'user32', 'CharToOemBuffA', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			["DWORD","cchDstLength","in"],
			])

		railgun.add_function( 'user32', 'CharToOemBuffW', 'BOOL',[
			["PWCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			["DWORD","cchDstLength","in"],
			])

		railgun.add_function( 'user32', 'CharToOemW', 'BOOL',[
			["PWCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			])

		railgun.add_function( 'user32', 'CharUpperBuffA', 'DWORD',[
			["PCHAR","lpsz","in"],
			["DWORD","cchLength","in"],
			])

		railgun.add_function( 'user32', 'CharUpperBuffW', 'DWORD',[
			["PWCHAR","lpsz","in"],
			["DWORD","cchLength","in"],
			])

		railgun.add_function( 'user32', 'CheckDlgButton', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDButton","in"],
			["DWORD","uCheck","in"],
			])

		railgun.add_function( 'user32', 'CheckMenuItem', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","uIDCheckItem","in"],
			["DWORD","uCheck","in"],
			])

		railgun.add_function( 'user32', 'CheckMenuRadioItem', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","first","in"],
			["DWORD","last","in"],
			["DWORD","check","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'CheckRadioButton', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDFirstButton","in"],
			["DWORD","nIDLastButton","in"],
			["DWORD","nIDCheckButton","in"],
			])

		railgun.add_function( 'user32', 'ChildWindowFromPoint', 'DWORD',[
			["DWORD","hWndParent","in"],
			["PBLOB","Point","in"],
			])

		railgun.add_function( 'user32', 'ChildWindowFromPointEx', 'DWORD',[
			["DWORD","hwnd","in"],
			["PBLOB","pt","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'ClientToScreen', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpPoint","inout"],
			])

		railgun.add_function( 'user32', 'ClipCursor', 'BOOL',[
			["PBLOB","lpRect","in"],
			])

		railgun.add_function( 'user32', 'CloseClipboard', 'BOOL',[
			])

		railgun.add_function( 'user32', 'CloseDesktop', 'BOOL',[
			["DWORD","hDesktop","in"],
			])

		railgun.add_function( 'user32', 'CloseWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'CloseWindowStation', 'BOOL',[
			["DWORD","hWinSta","in"],
			])

		railgun.add_function( 'user32', 'CopyAcceleratorTableA', 'DWORD',[
			["DWORD","hAccelSrc","in"],
			["PBLOB","lpAccelDst","out"],
			["DWORD","cAccelEntries","in"],
			])

		railgun.add_function( 'user32', 'CopyAcceleratorTableW', 'DWORD',[
			["DWORD","hAccelSrc","in"],
			["PBLOB","lpAccelDst","out"],
			["DWORD","cAccelEntries","in"],
			])

		railgun.add_function( 'user32', 'CopyIcon', 'DWORD',[
			["DWORD","hIcon","in"],
			])

		railgun.add_function( 'user32', 'CopyImage', 'DWORD',[
			["DWORD","h","in"],
			["DWORD","type","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'CopyRect', 'BOOL',[
			["PBLOB","lprcDst","out"],
			["PBLOB","lprcSrc","in"],
			])

		railgun.add_function( 'user32', 'CountClipboardFormats', 'DWORD',[
			])

		railgun.add_function( 'user32', 'CreateAcceleratorTableA', 'DWORD',[
			["PBLOB","paccel","in"],
			["DWORD","cAccel","in"],
			])

		railgun.add_function( 'user32', 'CreateAcceleratorTableW', 'DWORD',[
			["PBLOB","paccel","in"],
			["DWORD","cAccel","in"],
			])

		railgun.add_function( 'user32', 'CreateCaret', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hBitmap","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			])

		railgun.add_function( 'user32', 'CreateCursor', 'DWORD',[
			["DWORD","hInst","in"],
			["DWORD","xHotSpot","in"],
			["DWORD","yHotSpot","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			])

		railgun.add_function( 'user32', 'CreateDesktopA', 'DWORD',[
			["PCHAR","lpszDesktop","in"],
			["PCHAR","lpszDevice","inout"],
			["PBLOB","pDevmode","inout"],
			["DWORD","dwFlags","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpsa","in"],
			])

		railgun.add_function( 'user32', 'CreateDesktopW', 'DWORD',[
			["PWCHAR","lpszDesktop","in"],
			["PWCHAR","lpszDevice","inout"],
			["PBLOB","pDevmode","inout"],
			["DWORD","dwFlags","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpsa","in"],
			])

		railgun.add_function( 'user32', 'CreateDialogIndirectParamA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PBLOB","lpTemplate","in"],
			["DWORD","hWndParent","in"],
			["PBLOB","lpDialogFunc","in"],
			["DWORD","dwInitParam","in"],
			])

		railgun.add_function( 'user32', 'CreateDialogIndirectParamW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PBLOB","lpTemplate","in"],
			["DWORD","hWndParent","in"],
			["PBLOB","lpDialogFunc","in"],
			["DWORD","dwInitParam","in"],
			])

		railgun.add_function( 'user32', 'CreateDialogParamA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpTemplateName","in"],
			["DWORD","hWndParent","in"],
			["PBLOB","lpDialogFunc","in"],
			["DWORD","dwInitParam","in"],
			])

		railgun.add_function( 'user32', 'CreateDialogParamW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpTemplateName","in"],
			["DWORD","hWndParent","in"],
			["PBLOB","lpDialogFunc","in"],
			["DWORD","dwInitParam","in"],
			])

		railgun.add_function( 'user32', 'CreateIcon', 'DWORD',[
			["DWORD","hInstance","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["BYTE","cPlanes","in"],
			["BYTE","cBitsPixel","in"],
			["PBLOB","lpbANDbits","in"],
			["PBLOB","lpbXORbits","in"],
			])

		railgun.add_function( 'user32', 'CreateIconFromResource', 'DWORD',[
			["PBLOB","presbits","in"],
			["DWORD","dwResSize","in"],
			["BOOL","fIcon","in"],
			["DWORD","dwVer","in"],
			])

		railgun.add_function( 'user32', 'CreateIconFromResourceEx', 'DWORD',[
			["PBLOB","presbits","in"],
			["DWORD","dwResSize","in"],
			["BOOL","fIcon","in"],
			["DWORD","dwVer","in"],
			["DWORD","cxDesired","in"],
			["DWORD","cyDesired","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'CreateIconIndirect', 'DWORD',[
			["PBLOB","piconinfo","in"],
			])

		railgun.add_function( 'user32', 'CreateMDIWindowA', 'DWORD',[
			["PCHAR","lpClassName","in"],
			["PCHAR","lpWindowName","in"],
			["DWORD","dwStyle","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["DWORD","hWndParent","in"],
			["DWORD","hInstance","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CreateMDIWindowW', 'DWORD',[
			["PWCHAR","lpClassName","in"],
			["PWCHAR","lpWindowName","in"],
			["DWORD","dwStyle","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["DWORD","hWndParent","in"],
			["DWORD","hInstance","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CreateMenu', 'DWORD',[
			])

		railgun.add_function( 'user32', 'CreatePopupMenu', 'DWORD',[
			])

		railgun.add_function( 'user32', 'CreateWindowExA', 'DWORD',[
			["DWORD","dwExStyle","in"],
			["PCHAR","lpClassName","in"],
			["PCHAR","lpWindowName","in"],
			["DWORD","dwStyle","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["DWORD","hWndParent","in"],
			["DWORD","hMenu","in"],
			["DWORD","hInstance","in"],
			["PBLOB","lpParam","in"],
			])

		railgun.add_function( 'user32', 'CreateWindowExW', 'DWORD',[
			["DWORD","dwExStyle","in"],
			["PWCHAR","lpClassName","in"],
			["PWCHAR","lpWindowName","in"],
			["DWORD","dwStyle","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["DWORD","hWndParent","in"],
			["DWORD","hMenu","in"],
			["DWORD","hInstance","in"],
			["PBLOB","lpParam","in"],
			])

		railgun.add_function( 'user32', 'CreateWindowStationA', 'DWORD',[
			["PCHAR","lpwinsta","in"],
			["DWORD","dwFlags","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpsa","in"],
			])

		railgun.add_function( 'user32', 'CreateWindowStationW', 'DWORD',[
			["PWCHAR","lpwinsta","in"],
			["DWORD","dwFlags","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpsa","in"],
			])

		railgun.add_function( 'user32', 'DefDlgProcA', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefDlgProcW', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefFrameProcA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hWndMDIClient","in"],
			["DWORD","uMsg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefFrameProcW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hWndMDIClient","in"],
			["DWORD","uMsg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefMDIChildProcA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","uMsg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefMDIChildProcW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","uMsg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefRawInputProc', 'DWORD',[
			["PBLOB","paRawInput","in"],
			["DWORD","nInput","in"],
			["DWORD","cbSizeHeader","in"],
			])

		railgun.add_function( 'user32', 'DefWindowProcA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefWindowProcW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DeferWindowPos', 'DWORD',[
			["DWORD","hWinPosInfo","in"],
			["DWORD","hWnd","in"],
			["DWORD","hWndInsertAfter","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'DeleteMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'DeregisterShellHookWindow', 'BOOL',[
			["DWORD","hwnd","in"],
			])

		railgun.add_function( 'user32', 'DestroyAcceleratorTable', 'BOOL',[
			["DWORD","hAccel","in"],
			])

		railgun.add_function( 'user32', 'DestroyCaret', 'BOOL',[
			])

		railgun.add_function( 'user32', 'DestroyCursor', 'BOOL',[
			["DWORD","hCursor","in"],
			])

		railgun.add_function( 'user32', 'DestroyIcon', 'BOOL',[
			["DWORD","hIcon","in"],
			])

		railgun.add_function( 'user32', 'DestroyMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			])

		railgun.add_function( 'user32', 'DestroyWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'DisableProcessWindowsGhosting', 'VOID',[
			])

		railgun.add_function( 'user32', 'DispatchMessageA', 'DWORD',[
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'DispatchMessageW', 'DWORD',[
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'DlgDirListA', 'DWORD',[
			["DWORD","hDlg","in"],
			["PCHAR","lpPathSpec","inout"],
			["DWORD","nIDListBox","in"],
			["DWORD","nIDStaticPath","in"],
			["DWORD","uFileType","in"],
			])

		railgun.add_function( 'user32', 'DlgDirListComboBoxA', 'DWORD',[
			["DWORD","hDlg","in"],
			["PCHAR","lpPathSpec","inout"],
			["DWORD","nIDComboBox","in"],
			["DWORD","nIDStaticPath","in"],
			["DWORD","uFiletype","in"],
			])

		railgun.add_function( 'user32', 'DlgDirListComboBoxW', 'DWORD',[
			["DWORD","hDlg","in"],
			["PWCHAR","lpPathSpec","inout"],
			["DWORD","nIDComboBox","in"],
			["DWORD","nIDStaticPath","in"],
			["DWORD","uFiletype","in"],
			])

		railgun.add_function( 'user32', 'DlgDirListW', 'DWORD',[
			["DWORD","hDlg","in"],
			["PWCHAR","lpPathSpec","inout"],
			["DWORD","nIDListBox","in"],
			["DWORD","nIDStaticPath","in"],
			["DWORD","uFileType","in"],
			])

		railgun.add_function( 'user32', 'DlgDirSelectComboBoxExA', 'BOOL',[
			["DWORD","hwndDlg","in"],
			["PCHAR","lpString","out"],
			["DWORD","cchOut","in"],
			["DWORD","idComboBox","in"],
			])

		railgun.add_function( 'user32', 'DlgDirSelectComboBoxExW', 'BOOL',[
			["DWORD","hwndDlg","in"],
			["PWCHAR","lpString","out"],
			["DWORD","cchOut","in"],
			["DWORD","idComboBox","in"],
			])

		railgun.add_function( 'user32', 'DlgDirSelectExA', 'BOOL',[
			["DWORD","hwndDlg","in"],
			["PCHAR","lpString","out"],
			["DWORD","chCount","in"],
			["DWORD","idListBox","in"],
			])

		railgun.add_function( 'user32', 'DlgDirSelectExW', 'BOOL',[
			["DWORD","hwndDlg","in"],
			["PWCHAR","lpString","out"],
			["DWORD","chCount","in"],
			["DWORD","idListBox","in"],
			])

		railgun.add_function( 'user32', 'DragDetect', 'BOOL',[
			["DWORD","hwnd","in"],
			["PBLOB","pt","in"],
			])

		railgun.add_function( 'user32', 'DragObject', 'DWORD',[
			["DWORD","hwndParent","in"],
			["DWORD","hwndFrom","in"],
			["DWORD","fmt","in"],
			["PDWORD","data","in"],
			["DWORD","hcur","in"],
			])

		railgun.add_function( 'user32', 'DrawAnimatedRects', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","idAni","in"],
			["PBLOB","lprcFrom","in"],
			["PBLOB","lprcTo","in"],
			])

		railgun.add_function( 'user32', 'DrawCaption', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","hdc","in"],
			["PBLOB","lprect","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'DrawEdge', 'BOOL',[
			["DWORD","hdc","in"],
			["PBLOB","qrc","inout"],
			["DWORD","edge","in"],
			["DWORD","grfFlags","in"],
			])

		railgun.add_function( 'user32', 'DrawFocusRect', 'BOOL',[
			["DWORD","hDC","in"],
			["PBLOB","lprc","in"],
			])

		railgun.add_function( 'user32', 'DrawIcon', 'BOOL',[
			["DWORD","hDC","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","hIcon","in"],
			])

		railgun.add_function( 'user32', 'DrawIconEx', 'BOOL',[
			["DWORD","hdc","in"],
			["DWORD","xLeft","in"],
			["DWORD","yTop","in"],
			["DWORD","hIcon","in"],
			["DWORD","cxWidth","in"],
			["DWORD","cyWidth","in"],
			["DWORD","istepIfAniCur","in"],
			["DWORD","hbrFlickerFreeDraw","in"],
			["DWORD","diFlags","in"],
			])

		railgun.add_function( 'user32', 'DrawMenuBar', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'DrawStateA', 'BOOL',[
			["DWORD","hdc","in"],
			["DWORD","hbrFore","in"],
			["PBLOB","qfnCallBack","in"],
			["DWORD","lData","in"],
			["WORD","wData","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'DrawStateW', 'BOOL',[
			["DWORD","hdc","in"],
			["DWORD","hbrFore","in"],
			["PBLOB","qfnCallBack","in"],
			["DWORD","lData","in"],
			["WORD","wData","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'DrawTextA', 'DWORD',[
			["DWORD","hdc","in"],
			["PCHAR","lpchText","in"],
			["DWORD","cchText","in"],
			["PBLOB","lprc","inout"],
			["DWORD","format","in"],
			])

		railgun.add_function( 'user32', 'DrawTextExA', 'DWORD',[
			["DWORD","hdc","in"],
			["PCHAR","lpchText","in"],
			["DWORD","cchText","in"],
			["PBLOB","lprc","inout"],
			["DWORD","format","in"],
			["PBLOB","lpdtp","in"],
			])

		railgun.add_function( 'user32', 'DrawTextExW', 'DWORD',[
			["DWORD","hdc","in"],
			["PWCHAR","lpchText","in"],
			["DWORD","cchText","in"],
			["PBLOB","lprc","inout"],
			["DWORD","format","in"],
			["PBLOB","lpdtp","in"],
			])

		railgun.add_function( 'user32', 'DrawTextW', 'DWORD',[
			["DWORD","hdc","in"],
			["PWCHAR","lpchText","in"],
			["DWORD","cchText","in"],
			["PBLOB","lprc","inout"],
			["DWORD","format","in"],
			])

		railgun.add_function( 'user32', 'EmptyClipboard', 'BOOL',[
			])

		railgun.add_function( 'user32', 'EnableMenuItem', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uIDEnableItem","in"],
			["DWORD","uEnable","in"],
			])

		railgun.add_function( 'user32', 'EnableScrollBar', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","wSBflags","in"],
			["DWORD","wArrows","in"],
			])

		railgun.add_function( 'user32', 'EnableWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["BOOL","bEnable","in"],
			])

		railgun.add_function( 'user32', 'EndDeferWindowPos', 'BOOL',[
			["DWORD","hWinPosInfo","in"],
			])

		railgun.add_function( 'user32', 'EndDialog', 'BOOL',[
			["DWORD","hDlg","in"],
			["PDWORD","nResult","in"],
			])

		railgun.add_function( 'user32', 'EndMenu', 'BOOL',[
			])

		railgun.add_function( 'user32', 'EndPaint', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpPaint","in"],
			])

		railgun.add_function( 'user32', 'EndTask', 'BOOL',[
			["DWORD","hWnd","in"],
			["BOOL","fShutDown","in"],
			["BOOL","fForce","in"],
			])

		railgun.add_function( 'user32', 'EnumChildWindows', 'BOOL',[
			["DWORD","hWndParent","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumClipboardFormats', 'DWORD',[
			["DWORD","format","in"],
			])

		railgun.add_function( 'user32', 'EnumDesktopWindows', 'BOOL',[
			["DWORD","hDesktop","in"],
			["PBLOB","lpfn","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumDesktopsA', 'BOOL',[
			["DWORD","hwinsta","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumDesktopsW', 'BOOL',[
			["DWORD","hwinsta","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplayDevicesA', 'BOOL',[
			["PCHAR","lpDevice","in"],
			["DWORD","iDevNum","in"],
			["PBLOB","lpDisplayDevice","inout"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplayDevicesW', 'BOOL',[
			["PWCHAR","lpDevice","in"],
			["DWORD","iDevNum","in"],
			["PBLOB","lpDisplayDevice","inout"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplayMonitors', 'BOOL',[
			["DWORD","hdc","in"],
			["PBLOB","lprcClip","in"],
			["PBLOB","lpfnEnum","in"],
			["DWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplaySettingsA', 'BOOL',[
			["PCHAR","lpszDeviceName","in"],
			["DWORD","iModeNum","in"],
			["PBLOB","lpDevMode","out"],
			])

		railgun.add_function( 'user32', 'EnumDisplaySettingsExA', 'BOOL',[
			["PCHAR","lpszDeviceName","in"],
			["DWORD","iModeNum","in"],
			["PBLOB","lpDevMode","out"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplaySettingsExW', 'BOOL',[
			["PWCHAR","lpszDeviceName","in"],
			["DWORD","iModeNum","in"],
			["PBLOB","lpDevMode","out"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplaySettingsW', 'BOOL',[
			["PWCHAR","lpszDeviceName","in"],
			["DWORD","iModeNum","in"],
			["PBLOB","lpDevMode","out"],
			])

		railgun.add_function( 'user32', 'EnumPropsA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpEnumFunc","in"],
			])

		railgun.add_function( 'user32', 'EnumPropsExA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumPropsExW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumPropsW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpEnumFunc","in"],
			])

		railgun.add_function( 'user32', 'EnumThreadWindows', 'BOOL',[
			["DWORD","dwThreadId","in"],
			["PBLOB","lpfn","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumWindowStationsA', 'BOOL',[
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumWindowStationsW', 'BOOL',[
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumWindows', 'BOOL',[
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EqualRect', 'BOOL',[
			["PBLOB","lprc1","in"],
			["PBLOB","lprc2","in"],
			])

		railgun.add_function( 'user32', 'ExcludeUpdateRgn', 'DWORD',[
			["DWORD","hDC","in"],
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'ExitWindowsEx', 'BOOL',[
			["DWORD","uFlags","in"],
			["DWORD","dwReason","in"],
			])

		railgun.add_function( 'user32', 'FillRect', 'DWORD',[
			["DWORD","hDC","in"],
			["PBLOB","lprc","in"],
			["DWORD","hbr","in"],
			])

		railgun.add_function( 'user32', 'FindWindowA', 'DWORD',[
			["PCHAR","lpClassName","in"],
			["PCHAR","lpWindowName","in"],
			])

		railgun.add_function( 'user32', 'FindWindowExA', 'DWORD',[
			["DWORD","hWndParent","in"],
			["DWORD","hWndChildAfter","in"],
			["PCHAR","lpszClass","in"],
			["PCHAR","lpszWindow","in"],
			])

		railgun.add_function( 'user32', 'FindWindowExW', 'DWORD',[
			["DWORD","hWndParent","in"],
			["DWORD","hWndChildAfter","in"],
			["PWCHAR","lpszClass","in"],
			["PWCHAR","lpszWindow","in"],
			])

		railgun.add_function( 'user32', 'FindWindowW', 'DWORD',[
			["PWCHAR","lpClassName","in"],
			["PWCHAR","lpWindowName","in"],
			])

		railgun.add_function( 'user32', 'FlashWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["BOOL","bInvert","in"],
			])

		railgun.add_function( 'user32', 'FlashWindowEx', 'BOOL',[
			["PBLOB","pfwi","in"],
			])

		railgun.add_function( 'user32', 'FrameRect', 'DWORD',[
			["DWORD","hDC","in"],
			["PBLOB","lprc","in"],
			["DWORD","hbr","in"],
			])

		railgun.add_function( 'user32', 'GetActiveWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetAltTabInfoA', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","iItem","in"],
			["PBLOB","pati","inout"],
			["PCHAR","pszItemText","out"],
			["DWORD","cchItemText","in"],
			])

		railgun.add_function( 'user32', 'GetAltTabInfoW', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","iItem","in"],
			["PBLOB","pati","inout"],
			["PWCHAR","pszItemText","out"],
			["DWORD","cchItemText","in"],
			])

		railgun.add_function( 'user32', 'GetAncestor', 'DWORD',[
			["DWORD","hwnd","in"],
			["DWORD","gaFlags","in"],
			])

		railgun.add_function( 'user32', 'GetAsyncKeyState', 'WORD',[
			["DWORD","vKey","in"],
			])

		railgun.add_function( 'user32', 'GetCapture', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetCaretBlinkTime', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetCaretPos', 'BOOL',[
			["PBLOB","lpPoint","out"],
			])

		railgun.add_function( 'user32', 'GetClassInfoA', 'BOOL',[
			["DWORD","hInstance","in"],
			["PCHAR","lpClassName","in"],
			["PBLOB","lpWndClass","out"],
			])

		railgun.add_function( 'user32', 'GetClassInfoExA', 'BOOL',[
			["DWORD","hInstance","in"],
			["PCHAR","lpszClass","in"],
			["PBLOB","lpwcx","out"],
			])

		railgun.add_function( 'user32', 'GetClassInfoExW', 'BOOL',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpszClass","in"],
			["PBLOB","lpwcx","out"],
			])

		railgun.add_function( 'user32', 'GetClassInfoW', 'BOOL',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpClassName","in"],
			["PBLOB","lpWndClass","out"],
			])

		railgun.add_function( 'user32', 'GetClassLongA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetClassLongW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetClassNameA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpClassName","out"],
			["DWORD","nMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetClassNameW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpClassName","out"],
			["DWORD","nMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetClassWord', 'WORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetClientRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","out"],
			])

		railgun.add_function( 'user32', 'GetClipCursor', 'BOOL',[
			["PBLOB","lpRect","out"],
			])

		railgun.add_function( 'user32', 'GetClipboardData', 'DWORD',[
			["DWORD","uFormat","in"],
			])

		railgun.add_function( 'user32', 'GetClipboardFormatNameA', 'DWORD',[
			["DWORD","format","in"],
			["PCHAR","lpszFormatName","out"],
			["DWORD","cchMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetClipboardFormatNameW', 'DWORD',[
			["DWORD","format","in"],
			["PWCHAR","lpszFormatName","out"],
			["DWORD","cchMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetClipboardOwner', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetClipboardSequenceNumber', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetClipboardViewer', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetComboBoxInfo', 'BOOL',[
			["DWORD","hwndCombo","in"],
			["PBLOB","pcbi","inout"],
			])

		railgun.add_function( 'user32', 'GetCursor', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetCursorInfo', 'BOOL',[
			["PBLOB","pci","inout"],
			])

		railgun.add_function( 'user32', 'GetCursorPos', 'BOOL',[
			["PBLOB","lpPoint","out"],
			])

		railgun.add_function( 'user32', 'GetDC', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetDCEx', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hrgnClip","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'GetDesktopWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetDialogBaseUnits', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetDlgCtrlID', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetDlgItem', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			])

		railgun.add_function( 'user32', 'GetDlgItemInt', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PBLOB","lpTranslated","out"],
			["BOOL","bSigned","in"],
			])

		railgun.add_function( 'user32', 'GetDlgItemTextA', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PCHAR","lpString","out"],
			["DWORD","cchMax","in"],
			])

		railgun.add_function( 'user32', 'GetDlgItemTextW', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PWCHAR","lpString","out"],
			["DWORD","cchMax","in"],
			])

		railgun.add_function( 'user32', 'GetDoubleClickTime', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetFocus', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetForegroundWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetGUIThreadInfo', 'BOOL',[
			["DWORD","idThread","in"],
			["PBLOB","pgui","inout"],
			])

		railgun.add_function( 'user32', 'GetGuiResources', 'DWORD',[
			["DWORD","hProcess","in"],
			["DWORD","uiFlags","in"],
			])

		railgun.add_function( 'user32', 'GetIconInfo', 'BOOL',[
			["DWORD","hIcon","in"],
			["PBLOB","piconinfo","out"],
			])

		railgun.add_function( 'user32', 'GetInputState', 'BOOL',[
			])

		railgun.add_function( 'user32', 'GetKBCodePage', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetKeyNameTextA', 'DWORD',[
			["DWORD","lParam","in"],
			["PCHAR","lpString","out"],
			["DWORD","cchSize","in"],
			])

		railgun.add_function( 'user32', 'GetKeyNameTextW', 'DWORD',[
			["DWORD","lParam","in"],
			["PWCHAR","lpString","out"],
			["DWORD","cchSize","in"],
			])

		railgun.add_function( 'user32', 'GetKeyState', 'WORD',[
			["DWORD","nVirtKey","in"],
			])

		railgun.add_function( 'user32', 'GetKeyboardLayout', 'DWORD',[
			["DWORD","idThread","in"],
			])

		railgun.add_function( 'user32', 'GetKeyboardType', 'DWORD',[
			["DWORD","nTypeFlag","in"],
			])

		railgun.add_function( 'user32', 'GetLastActivePopup', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetLastInputInfo', 'BOOL',[
			["PBLOB","plii","out"],
			])

		railgun.add_function( 'user32', 'GetLayeredWindowAttributes', 'BOOL',[
			["DWORD","hwnd","in"],
			["PDWORD","pcrKey","out"],
			["PBLOB","pbAlpha","out"],
			["PDWORD","pdwFlags","out"],
			])

		railgun.add_function( 'user32', 'GetListBoxInfo', 'DWORD',[
			["DWORD","hwnd","in"],
			])

		railgun.add_function( 'user32', 'GetMenu', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetMenuBarInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","idObject","in"],
			["DWORD","idItem","in"],
			["PBLOB","pmbi","inout"],
			])

		railgun.add_function( 'user32', 'GetMenuCheckMarkDimensions', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetMenuDefaultItem', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","fByPos","in"],
			["DWORD","gmdiFlags","in"],
			])

		railgun.add_function( 'user32', 'GetMenuInfo', 'BOOL',[
			["DWORD","param0","in"],
			["PBLOB","param1","inout"],
			])

		railgun.add_function( 'user32', 'GetMenuItemCount', 'DWORD',[
			["DWORD","hMenu","in"],
			])

		railgun.add_function( 'user32', 'GetMenuItemID', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","nPos","in"],
			])

		railgun.add_function( 'user32', 'GetMenuItemInfoA', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","item","in"],
			["BOOL","fByPosition","in"],
			["PBLOB","lpmii","inout"],
			])

		railgun.add_function( 'user32', 'GetMenuItemInfoW', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","item","in"],
			["BOOL","fByPosition","in"],
			["PBLOB","lpmii","inout"],
			])

		railgun.add_function( 'user32', 'GetMenuItemRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hMenu","in"],
			["DWORD","uItem","in"],
			["PBLOB","lprcItem","out"],
			])

		railgun.add_function( 'user32', 'GetMenuState', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","uId","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'GetMenuStringA', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","uIDItem","in"],
			["PCHAR","lpString","out"],
			["DWORD","cchMax","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'GetMenuStringW', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","uIDItem","in"],
			["PWCHAR","lpString","out"],
			["DWORD","cchMax","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'GetMessageA', 'BOOL',[
			["PBLOB","lpMsg","out"],
			["DWORD","hWnd","in"],
			["DWORD","wMsgFilterMin","in"],
			["DWORD","wMsgFilterMax","in"],
			])

		railgun.add_function( 'user32', 'GetMessageExtraInfo', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetMessagePos', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetMessageTime', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetMessageW', 'BOOL',[
			["PBLOB","lpMsg","out"],
			["DWORD","hWnd","in"],
			["DWORD","wMsgFilterMin","in"],
			["DWORD","wMsgFilterMax","in"],
			])

		railgun.add_function( 'user32', 'GetMonitorInfoA', 'BOOL',[
			["DWORD","hMonitor","in"],
			["PBLOB","lpmi","inout"],
			])

		railgun.add_function( 'user32', 'GetMonitorInfoW', 'BOOL',[
			["DWORD","hMonitor","in"],
			["PBLOB","lpmi","inout"],
			])

		railgun.add_function( 'user32', 'GetMouseMovePointsEx', 'DWORD',[
			["DWORD","cbSize","in"],
			["PBLOB","lppt","in"],
			["PBLOB","lpptBuf","out"],
			["DWORD","nBufPoints","in"],
			["DWORD","resolution","in"],
			])

		railgun.add_function( 'user32', 'GetNextDlgGroupItem', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","hCtl","in"],
			["BOOL","bPrevious","in"],
			])

		railgun.add_function( 'user32', 'GetNextDlgTabItem', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","hCtl","in"],
			["BOOL","bPrevious","in"],
			])

		railgun.add_function( 'user32', 'GetOpenClipboardWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetParent', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetPriorityClipboardFormat', 'DWORD',[
			["PDWORD","paFormatPriorityList","in"],
			["DWORD","cFormats","in"],
			])

		railgun.add_function( 'user32', 'GetProcessDefaultLayout', 'BOOL',[
			["PDWORD","pdwDefaultLayout","out"],
			])

		railgun.add_function( 'user32', 'GetProcessWindowStation', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetPropA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'GetPropW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'GetQueueStatus', 'DWORD',[
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'GetRawInputBuffer', 'DWORD',[
			["PBLOB","pData","out"],
			["PDWORD","pcbSize","inout"],
			["DWORD","cbSizeHeader","in"],
			])

		railgun.add_function( 'user32', 'GetRawInputData', 'DWORD',[
			["DWORD","hRawInput","in"],
			["DWORD","uiCommand","in"],
			["PBLOB","pData","out"],
			["PDWORD","pcbSize","inout"],
			["DWORD","cbSizeHeader","in"],
			])

		railgun.add_function( 'user32', 'GetRawInputDeviceInfoA', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","uiCommand","in"],
			["PBLOB","pData","inout"],
			["PDWORD","pcbSize","inout"],
			])

		railgun.add_function( 'user32', 'GetRawInputDeviceInfoW', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","uiCommand","in"],
			["PBLOB","pData","inout"],
			["PDWORD","pcbSize","inout"],
			])

		railgun.add_function( 'user32', 'GetRawInputDeviceList', 'DWORD',[
			["PBLOB","pRawInputDeviceList","out"],
			["PDWORD","puiNumDevices","inout"],
			["DWORD","cbSize","in"],
			])

		railgun.add_function( 'user32', 'GetRegisteredRawInputDevices', 'DWORD',[
			["PBLOB","pRawInputDevices","out"],
			["PDWORD","puiNumDevices","inout"],
			["DWORD","cbSize","in"],
			])

		railgun.add_function( 'user32', 'GetScrollBarInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","idObject","in"],
			["PBLOB","psbi","inout"],
			])

		railgun.add_function( 'user32', 'GetScrollInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","nBar","in"],
			["PBLOB","lpsi","inout"],
			])

		railgun.add_function( 'user32', 'GetScrollPos', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nBar","in"],
			])

		railgun.add_function( 'user32', 'GetScrollRange', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","nBar","in"],
			["PDWORD","lpMinPos","out"],
			["PDWORD","lpMaxPos","out"],
			])

		railgun.add_function( 'user32', 'GetShellWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetSubMenu', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","nPos","in"],
			])

		railgun.add_function( 'user32', 'GetSysColor', 'DWORD',[
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetSysColorBrush', 'DWORD',[
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetSystemMenu', 'DWORD',[
			["DWORD","hWnd","in"],
			["BOOL","bRevert","in"],
			])

		railgun.add_function( 'user32', 'GetSystemMetrics', 'DWORD',[
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetThreadDesktop', 'DWORD',[
			["DWORD","dwThreadId","in"],
			])

		railgun.add_function( 'user32', 'GetTitleBarInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["PBLOB","pti","inout"],
			])

		railgun.add_function( 'user32', 'GetTopWindow', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetUpdateRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","out"],
			["BOOL","bErase","in"],
			])

		railgun.add_function( 'user32', 'GetUpdateRgn', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			["BOOL","bErase","in"],
			])

		railgun.add_function( 'user32', 'GetUserObjectInformationA', 'BOOL',[
			["DWORD","hObj","in"],
			["DWORD","nIndex","in"],
			["PBLOB","pvInfo","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'user32', 'GetUserObjectInformationW', 'BOOL',[
			["DWORD","hObj","in"],
			["DWORD","nIndex","in"],
			["PBLOB","pvInfo","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'user32', 'GetUserObjectSecurity', 'BOOL',[
			["DWORD","hObj","in"],
			["PBLOB","pSIRequested","in"],
			["PBLOB","pSID","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'user32', 'GetWindow', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","uCmd","in"],
			])

		railgun.add_function( 'user32', 'GetWindowContextHelpId', 'DWORD',[
			["DWORD","param0","in"],
			])

		railgun.add_function( 'user32', 'GetWindowDC', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetWindowInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["PBLOB","pwi","inout"],
			])

		railgun.add_function( 'user32', 'GetWindowLongA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetWindowLongW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetWindowModuleFileNameA', 'DWORD',[
			["DWORD","hwnd","in"],
			["PCHAR","pszFileName","out"],
			["DWORD","cchFileNameMax","in"],
			])

		railgun.add_function( 'user32', 'GetWindowModuleFileNameW', 'DWORD',[
			["DWORD","hwnd","in"],
			["PWCHAR","pszFileName","out"],
			["DWORD","cchFileNameMax","in"],
			])

		railgun.add_function( 'user32', 'GetWindowPlacement', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpwndpl","inout"],
			])

		railgun.add_function( 'user32', 'GetWindowRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","out"],
			])

		railgun.add_function( 'user32', 'GetWindowRgn', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			])

		railgun.add_function( 'user32', 'GetWindowRgnBox', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lprc","out"],
			])

		railgun.add_function( 'user32', 'GetWindowTextA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","out"],
			["DWORD","nMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetWindowTextLengthA', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetWindowTextLengthW', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetWindowTextW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","out"],
			["DWORD","nMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetWindowThreadProcessId', 'DWORD',[
			["DWORD","hWnd","in"],
			["PDWORD","lpdwProcessId","out"],
			])

		railgun.add_function( 'user32', 'GetWindowWord', 'WORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GrayStringA', 'BOOL',[
			["DWORD","hDC","in"],
			["DWORD","hBrush","in"],
			["PBLOB","lpOutputFunc","in"],
			["DWORD","lpData","in"],
			["DWORD","nCount","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			])

		railgun.add_function( 'user32', 'GrayStringW', 'BOOL',[
			["DWORD","hDC","in"],
			["DWORD","hBrush","in"],
			["PBLOB","lpOutputFunc","in"],
			["DWORD","lpData","in"],
			["DWORD","nCount","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			])

		railgun.add_function( 'user32', 'HideCaret', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'HiliteMenuItem', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hMenu","in"],
			["DWORD","uIDHiliteItem","in"],
			["DWORD","uHilite","in"],
			])

		railgun.add_function( 'user32', 'InSendMessage', 'BOOL',[
			])

		railgun.add_function( 'user32', 'InSendMessageEx', 'DWORD',[
			["PBLOB","lpReserved","inout"],
			])

		railgun.add_function( 'user32', 'InflateRect', 'BOOL',[
			["PBLOB","lprc","inout"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			])

		railgun.add_function( 'user32', 'InsertMenuA', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'InsertMenuItemW', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","item","in"],
			["BOOL","fByPosition","in"],
			["PBLOB","lpmi","in"],
			])

		railgun.add_function( 'user32', 'InsertMenuW', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PWCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'InternalGetWindowText', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","pString","out"],
			["DWORD","cchMaxCount","in"],
			])

		railgun.add_function( 'user32', 'IntersectRect', 'BOOL',[
			["PBLOB","lprcDst","out"],
			["PBLOB","lprcSrc1","in"],
			["PBLOB","lprcSrc2","in"],
			])

		railgun.add_function( 'user32', 'InvalidateRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","in"],
			["BOOL","bErase","in"],
			])

		railgun.add_function( 'user32', 'InvalidateRgn', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			["BOOL","bErase","in"],
			])

		railgun.add_function( 'user32', 'InvertRect', 'BOOL',[
			["DWORD","hDC","in"],
			["PBLOB","lprc","in"],
			])

		railgun.add_function( 'user32', 'IsCharAlphaA', 'BOOL',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharAlphaNumericA', 'BOOL',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharAlphaNumericW', 'BOOL',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharAlphaW', 'BOOL',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharLowerA', 'BOOL',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharLowerW', 'BOOL',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharUpperA', 'BOOL',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharUpperW', 'BOOL',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'IsChild', 'BOOL',[
			["DWORD","hWndParent","in"],
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsClipboardFormatAvailable', 'BOOL',[
			["DWORD","format","in"],
			])

		railgun.add_function( 'user32', 'IsDialogMessageA', 'BOOL',[
			["DWORD","hDlg","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'IsDialogMessageW', 'BOOL',[
			["DWORD","hDlg","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'IsDlgButtonChecked', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDButton","in"],
			])

		railgun.add_function( 'user32', 'IsGUIThread', 'BOOL',[
			["BOOL","bConvert","in"],
			])

		railgun.add_function( 'user32', 'IsHungAppWindow', 'BOOL',[
			["DWORD","hwnd","in"],
			])

		railgun.add_function( 'user32', 'IsIconic', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			])

		railgun.add_function( 'user32', 'IsRectEmpty', 'BOOL',[
			["PBLOB","lprc","in"],
			])

		railgun.add_function( 'user32', 'IsWinEventHookInstalled', 'BOOL',[
			["DWORD","event","in"],
			])

		railgun.add_function( 'user32', 'IsWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsWindowEnabled', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsWindowUnicode', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsWindowVisible', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsWow64Message', 'BOOL',[
			])

		railgun.add_function( 'user32', 'IsZoomed', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'KillTimer', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","uIDEvent","in"],
			])

		railgun.add_function( 'user32', 'LoadAcceleratorsA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpTableName","in"],
			])

		railgun.add_function( 'user32', 'LoadAcceleratorsW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpTableName","in"],
			])

		railgun.add_function( 'user32', 'LoadBitmapA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpBitmapName","in"],
			])

		railgun.add_function( 'user32', 'LoadBitmapW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpBitmapName","in"],
			])

		railgun.add_function( 'user32', 'LoadCursorA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpCursorName","in"],
			])

		railgun.add_function( 'user32', 'LoadCursorFromFileA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'user32', 'LoadCursorFromFileW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'user32', 'LoadCursorW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpCursorName","in"],
			])

		railgun.add_function( 'user32', 'LoadIconA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpIconName","in"],
			])

		railgun.add_function( 'user32', 'LoadIconW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpIconName","in"],
			])

		railgun.add_function( 'user32', 'LoadImageA', 'DWORD',[
			["DWORD","hInst","in"],
			["PCHAR","name","in"],
			["DWORD","type","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","fuLoad","in"],
			])

		railgun.add_function( 'user32', 'LoadImageW', 'DWORD',[
			["DWORD","hInst","in"],
			["PWCHAR","name","in"],
			["DWORD","type","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","fuLoad","in"],
			])

		railgun.add_function( 'user32', 'LoadKeyboardLayoutA', 'DWORD',[
			["PCHAR","pwszKLID","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'LoadKeyboardLayoutW', 'DWORD',[
			["PWCHAR","pwszKLID","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'LoadMenuA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpMenuName","in"],
			])

		railgun.add_function( 'user32', 'LoadMenuIndirectA', 'DWORD',[
			["PBLOB","lpMenuTemplate","in"],
			])

		railgun.add_function( 'user32', 'LoadMenuIndirectW', 'DWORD',[
			["PBLOB","lpMenuTemplate","in"],
			])

		railgun.add_function( 'user32', 'LoadMenuW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpMenuName","in"],
			])

		railgun.add_function( 'user32', 'LoadStringA', 'DWORD',[
			["DWORD","hInstance","in"],
			["DWORD","uID","in"],
			["PCHAR","lpBuffer","out"],
			["DWORD","cchBufferMax","in"],
			])

		railgun.add_function( 'user32', 'LoadStringW', 'DWORD',[
			["DWORD","hInstance","in"],
			["DWORD","uID","in"],
			["PWCHAR","lpBuffer","out"],
			["DWORD","cchBufferMax","in"],
			])

		railgun.add_function( 'user32', 'LockSetForegroundWindow', 'BOOL',[
			["DWORD","uLockCode","in"],
			])

		railgun.add_function( 'user32', 'LockWindowUpdate', 'BOOL',[
			["DWORD","hWndLock","in"],
			])

		railgun.add_function( 'user32', 'LockWorkStation', 'BOOL',[
			])

		railgun.add_function( 'user32', 'LookupIconIdFromDirectory', 'DWORD',[
			["PBLOB","presbits","in"],
			["BOOL","fIcon","in"],
			])

		railgun.add_function( 'user32', 'LookupIconIdFromDirectoryEx', 'DWORD',[
			["PBLOB","presbits","in"],
			["BOOL","fIcon","in"],
			["DWORD","cxDesired","in"],
			["DWORD","cyDesired","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'MapDialogRect', 'BOOL',[
			["DWORD","hDlg","in"],
			["PBLOB","lpRect","inout"],
			])

		railgun.add_function( 'user32', 'MapVirtualKeyA', 'DWORD',[
			["DWORD","uCode","in"],
			["DWORD","uMapType","in"],
			])

		railgun.add_function( 'user32', 'MapVirtualKeyExA', 'DWORD',[
			["DWORD","uCode","in"],
			["DWORD","uMapType","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'MapVirtualKeyExW', 'DWORD',[
			["DWORD","uCode","in"],
			["DWORD","uMapType","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'MapVirtualKeyW', 'DWORD',[
			["DWORD","uCode","in"],
			["DWORD","uMapType","in"],
			])

		railgun.add_function( 'user32', 'MapWindowPoints', 'DWORD',[
			["DWORD","hWndFrom","in"],
			["DWORD","hWndTo","in"],
			["PBLOB","lpPoints","in"],
			["DWORD","cPoints","in"],
			])

		railgun.add_function( 'user32', 'MenuItemFromPoint', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hMenu","in"],
			["PBLOB","ptScreen","in"],
			])

		railgun.add_function( 'user32', 'MessageBeep', 'BOOL',[
			["DWORD","uType","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpText","in"],
			["PCHAR","lpCaption","in"],
			["DWORD","uType","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxExA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpText","in"],
			["PCHAR","lpCaption","in"],
			["DWORD","uType","in"],
			["WORD","wLanguageId","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxExW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpText","in"],
			["PWCHAR","lpCaption","in"],
			["DWORD","uType","in"],
			["WORD","wLanguageId","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxIndirectA', 'DWORD',[
			["PBLOB","lpmbp","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxIndirectW', 'DWORD',[
			["PBLOB","lpmbp","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpText","in"],
			["PWCHAR","lpCaption","in"],
			["DWORD","uType","in"],
			])

		railgun.add_function( 'user32', 'ModifyMenuA', 'BOOL',[
			["DWORD","hMnu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'ModifyMenuW', 'BOOL',[
			["DWORD","hMnu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PWCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'MonitorFromPoint', 'DWORD',[
			["PBLOB","pt","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'MonitorFromRect', 'DWORD',[
			["PBLOB","lprc","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'MonitorFromWindow', 'DWORD',[
			["DWORD","hwnd","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'MoveWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["BOOL","bRepaint","in"],
			])

		railgun.add_function( 'user32', 'MsgWaitForMultipleObjects', 'DWORD',[
			["DWORD","nCount","in"],
			["PDWORD","pHandles","in"],
			["BOOL","fWaitAll","in"],
			["DWORD","dwMilliseconds","in"],
			["DWORD","dwWakeMask","in"],
			])

		railgun.add_function( 'user32', 'MsgWaitForMultipleObjectsEx', 'DWORD',[
			["DWORD","nCount","in"],
			["PDWORD","pHandles","in"],
			["DWORD","dwMilliseconds","in"],
			["DWORD","dwWakeMask","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'NotifyWinEvent', 'VOID',[
			["DWORD","event","in"],
			["DWORD","hwnd","in"],
			["DWORD","idObject","in"],
			["DWORD","idChild","in"],
			])

		railgun.add_function( 'user32', 'OemKeyScan', 'DWORD',[
			["WORD","wOemChar","in"],
			])

		railgun.add_function( 'user32', 'OemToCharA', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			])

		railgun.add_function( 'user32', 'OemToCharBuffA', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			["DWORD","cchDstLength","in"],
			])

		railgun.add_function( 'user32', 'OemToCharBuffW', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PWCHAR","lpszDst","out"],
			["DWORD","cchDstLength","in"],
			])

		railgun.add_function( 'user32', 'OemToCharW', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PWCHAR","lpszDst","out"],
			])

		railgun.add_function( 'user32', 'OffsetRect', 'BOOL',[
			["PBLOB","lprc","inout"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			])

		railgun.add_function( 'user32', 'OpenClipboard', 'BOOL',[
			["DWORD","hWndNewOwner","in"],
			])

		railgun.add_function( 'user32', 'OpenDesktopA', 'DWORD',[
			["PCHAR","lpszDesktop","in"],
			["DWORD","dwFlags","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'OpenDesktopW', 'DWORD',[
			["PWCHAR","lpszDesktop","in"],
			["DWORD","dwFlags","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'OpenIcon', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'OpenInputDesktop', 'DWORD',[
			["DWORD","dwFlags","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'OpenWindowStationA', 'DWORD',[
			["PCHAR","lpszWinSta","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'OpenWindowStationW', 'DWORD',[
			["PWCHAR","lpszWinSta","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'PaintDesktop', 'BOOL',[
			["DWORD","hdc","in"],
			])

		railgun.add_function( 'user32', 'PeekMessageA', 'BOOL',[
			["PBLOB","lpMsg","out"],
			["DWORD","hWnd","in"],
			["DWORD","wMsgFilterMin","in"],
			["DWORD","wMsgFilterMax","in"],
			["DWORD","wRemoveMsg","in"],
			])

		railgun.add_function( 'user32', 'PeekMessageW', 'BOOL',[
			["PBLOB","lpMsg","out"],
			["DWORD","hWnd","in"],
			["DWORD","wMsgFilterMin","in"],
			["DWORD","wMsgFilterMax","in"],
			["DWORD","wRemoveMsg","in"],
			])

		railgun.add_function( 'user32', 'PostMessageA', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'PostMessageW', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'PostQuitMessage', 'VOID',[
			["DWORD","nExitCode","in"],
			])

		railgun.add_function( 'user32', 'PostThreadMessageA', 'BOOL',[
			["DWORD","idThread","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'PostThreadMessageW', 'BOOL',[
			["DWORD","idThread","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'PrintWindow', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","hdcBlt","in"],
			["DWORD","nFlags","in"],
			])

		railgun.add_function( 'user32', 'PrivateExtractIconsA', 'DWORD',[
			["PCHAR","szFileName","in"],
			["DWORD","nIconIndex","in"],
			["DWORD","cxIcon","in"],
			["DWORD","cyIcon","in"],
			["PDWORD","phicon","out"],
			["PDWORD","piconid","out"],
			["DWORD","nIcons","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'PrivateExtractIconsW', 'DWORD',[
			["PWCHAR","szFileName","in"],
			["DWORD","nIconIndex","in"],
			["DWORD","cxIcon","in"],
			["DWORD","cyIcon","in"],
			["PDWORD","phicon","out"],
			["PDWORD","piconid","out"],
			["DWORD","nIcons","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'PtInRect', 'BOOL',[
			["PBLOB","lprc","in"],
			["PBLOB","pt","in"],
			])

		railgun.add_function( 'user32', 'RealChildWindowFromPoint', 'DWORD',[
			["DWORD","hwndParent","in"],
			["PBLOB","ptParentClientCoords","in"],
			])

		railgun.add_function( 'user32', 'RealGetWindowClassA', 'DWORD',[
			["DWORD","hwnd","in"],
			["PCHAR","ptszClassName","out"],
			["DWORD","cchClassNameMax","in"],
			])

		railgun.add_function( 'user32', 'RealGetWindowClassW', 'DWORD',[
			["DWORD","hwnd","in"],
			["PWCHAR","ptszClassName","out"],
			["DWORD","cchClassNameMax","in"],
			])

		railgun.add_function( 'user32', 'RedrawWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lprcUpdate","in"],
			["DWORD","hrgnUpdate","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'RegisterClassA', 'WORD',[
			["PBLOB","lpWndClass","in"],
			])

		railgun.add_function( 'user32', 'RegisterClassExA', 'WORD',[
			["PBLOB","param0","in"],
			])

		railgun.add_function( 'user32', 'RegisterClassExW', 'WORD',[
			["PBLOB","param0","in"],
			])

		railgun.add_function( 'user32', 'RegisterClassW', 'WORD',[
			["PBLOB","lpWndClass","in"],
			])

		railgun.add_function( 'user32', 'RegisterClipboardFormatA', 'DWORD',[
			["PCHAR","lpszFormat","in"],
			])

		railgun.add_function( 'user32', 'RegisterClipboardFormatW', 'DWORD',[
			["PWCHAR","lpszFormat","in"],
			])

		railgun.add_function( 'user32', 'RegisterDeviceNotificationA', 'DWORD',[
			["DWORD","hRecipient","in"],
			["PBLOB","NotificationFilter","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'RegisterDeviceNotificationW', 'DWORD',[
			["DWORD","hRecipient","in"],
			["PBLOB","NotificationFilter","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'RegisterHotKey', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","id","in"],
			["DWORD","fsModifiers","in"],
			["DWORD","vk","in"],
			])

		railgun.add_function( 'user32', 'RegisterRawInputDevices', 'BOOL',[
			["PBLOB","pRawInputDevices","in"],
			["DWORD","uiNumDevices","in"],
			["DWORD","cbSize","in"],
			])

		railgun.add_function( 'user32', 'RegisterShellHookWindow', 'BOOL',[
			["DWORD","hwnd","in"],
			])

		railgun.add_function( 'user32', 'RegisterWindowMessageA', 'DWORD',[
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'RegisterWindowMessageW', 'DWORD',[
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'ReleaseCapture', 'BOOL',[
			])

		railgun.add_function( 'user32', 'ReleaseDC', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hDC","in"],
			])

		railgun.add_function( 'user32', 'RemoveMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'RemovePropA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'RemovePropW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'ReplyMessage', 'BOOL',[
			["DWORD","lResult","in"],
			])

		railgun.add_function( 'user32', 'ScreenToClient', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpPoint","inout"],
			])

		railgun.add_function( 'user32', 'ScrollDC', 'BOOL',[
			["DWORD","hDC","in"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			["PBLOB","lprcScroll","in"],
			["PBLOB","lprcClip","in"],
			["DWORD","hrgnUpdate","in"],
			["PBLOB","lprcUpdate","out"],
			])

		railgun.add_function( 'user32', 'ScrollWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","XAmount","in"],
			["DWORD","YAmount","in"],
			["PBLOB","lpRect","in"],
			["PBLOB","lpClipRect","in"],
			])

		railgun.add_function( 'user32', 'ScrollWindowEx', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			["PBLOB","prcScroll","in"],
			["PBLOB","prcClip","in"],
			["DWORD","hrgnUpdate","in"],
			["PBLOB","prcUpdate","out"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'SendDlgItemMessageA', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendDlgItemMessageW', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendInput', 'DWORD',[
			["DWORD","cInputs","in"],
			["PBLOB","pInputs","in"],
			["DWORD","cbSize","in"],
			])

		railgun.add_function( 'user32', 'SendMessageA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendMessageCallbackA', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["PBLOB","lpResultCallBack","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'SendMessageCallbackW', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["PBLOB","lpResultCallBack","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'SendMessageTimeoutA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["DWORD","fuFlags","in"],
			["DWORD","uTimeout","in"],
			["PBLOB","lpdwResult","out"],
			])

		railgun.add_function( 'user32', 'SendMessageTimeoutW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["DWORD","fuFlags","in"],
			["DWORD","uTimeout","in"],
			["PBLOB","lpdwResult","out"],
			])

		railgun.add_function( 'user32', 'SendMessageW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendNotifyMessageA', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendNotifyMessageW', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SetActiveWindow', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'SetCapture', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'SetCaretBlinkTime', 'BOOL',[
			["DWORD","uMSeconds","in"],
			])

		railgun.add_function( 'user32', 'SetCaretPos', 'BOOL',[
			["DWORD","X","in"],
			["DWORD","Y","in"],
			])

		railgun.add_function( 'user32', 'SetClassLongA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["DWORD","dwNewLong","in"],
			])

		railgun.add_function( 'user32', 'SetClassLongW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["DWORD","dwNewLong","in"],
			])

		railgun.add_function( 'user32', 'SetClassWord', 'WORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["WORD","wNewWord","in"],
			])

		railgun.add_function( 'user32', 'SetClipboardData', 'DWORD',[
			["DWORD","uFormat","in"],
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'user32', 'SetClipboardViewer', 'DWORD',[
			["DWORD","hWndNewViewer","in"],
			])

		railgun.add_function( 'user32', 'SetCursor', 'DWORD',[
			["DWORD","hCursor","in"],
			])

		railgun.add_function( 'user32', 'SetCursorPos', 'BOOL',[
			["DWORD","X","in"],
			["DWORD","Y","in"],
			])

		railgun.add_function( 'user32', 'SetDebugErrorLevel', 'VOID',[
			["DWORD","dwLevel","in"],
			])

		railgun.add_function( 'user32', 'SetDlgItemInt', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["DWORD","uValue","in"],
			["BOOL","bSigned","in"],
			])

		railgun.add_function( 'user32', 'SetDlgItemTextA', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'SetDlgItemTextW', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'SetDoubleClickTime', 'BOOL',[
			["DWORD","param0","in"],
			])

		railgun.add_function( 'user32', 'SetFocus', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'SetForegroundWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'SetLastErrorEx', 'VOID',[
			["DWORD","dwErrCode","in"],
			["DWORD","dwType","in"],
			])

		railgun.add_function( 'user32', 'SetLayeredWindowAttributes', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","crKey","in"],
			["BYTE","bAlpha","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'SetMenu', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hMenu","in"],
			])

		railgun.add_function( 'user32', 'SetMenuContextHelpId', 'BOOL',[
			["DWORD","param0","in"],
			["DWORD","param1","in"],
			])

		railgun.add_function( 'user32', 'SetMenuDefaultItem', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uItem","in"],
			["DWORD","fByPos","in"],
			])

		railgun.add_function( 'user32', 'SetMenuInfo', 'BOOL',[
			["DWORD","param0","in"],
			["PBLOB","param1","in"],
			])

		railgun.add_function( 'user32', 'SetMenuItemBitmaps', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","hBitmapUnchecked","in"],
			["DWORD","hBitmapChecked","in"],
			])

		railgun.add_function( 'user32', 'SetMenuItemInfoW', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","item","in"],
			["BOOL","fByPositon","in"],
			["PBLOB","lpmii","in"],
			])

		railgun.add_function( 'user32', 'SetMessageExtraInfo', 'DWORD',[
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SetMessageQueue', 'BOOL',[
			["DWORD","cMessagesMax","in"],
			])

		railgun.add_function( 'user32', 'SetParent', 'DWORD',[
			["DWORD","hWndChild","in"],
			["DWORD","hWndNewParent","in"],
			])

		railgun.add_function( 'user32', 'SetProcessDefaultLayout', 'BOOL',[
			["DWORD","dwDefaultLayout","in"],
			])

		railgun.add_function( 'user32', 'SetProcessWindowStation', 'BOOL',[
			["DWORD","hWinSta","in"],
			])

		railgun.add_function( 'user32', 'SetPropA', 'BOOL',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","in"],
			["DWORD","hData","in"],
			])

		railgun.add_function( 'user32', 'SetPropW', 'BOOL',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","in"],
			["DWORD","hData","in"],
			])

		railgun.add_function( 'user32', 'SetRect', 'BOOL',[
			["PBLOB","lprc","out"],
			["DWORD","xLeft","in"],
			["DWORD","yTop","in"],
			["DWORD","xRight","in"],
			["DWORD","yBottom","in"],
			])

		railgun.add_function( 'user32', 'SetRectEmpty', 'BOOL',[
			["PBLOB","lprc","out"],
			])

		railgun.add_function( 'user32', 'SetScrollInfo', 'DWORD',[
			["DWORD","hwnd","in"],
			["DWORD","nBar","in"],
			["PBLOB","lpsi","in"],
			["BOOL","redraw","in"],
			])

		railgun.add_function( 'user32', 'SetScrollPos', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nBar","in"],
			["DWORD","nPos","in"],
			["BOOL","bRedraw","in"],
			])

		railgun.add_function( 'user32', 'SetScrollRange', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","nBar","in"],
			["DWORD","nMinPos","in"],
			["DWORD","nMaxPos","in"],
			["BOOL","bRedraw","in"],
			])

		railgun.add_function( 'user32', 'SetSystemCursor', 'BOOL',[
			["DWORD","hcur","in"],
			["DWORD","id","in"],
			])

		railgun.add_function( 'user32', 'SetThreadDesktop', 'BOOL',[
			["DWORD","hDesktop","in"],
			])

		railgun.add_function( 'user32', 'SetTimer', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIDEvent","in"],
			["DWORD","uElapse","in"],
			["PBLOB","lpTimerFunc","in"],
			])

		railgun.add_function( 'user32', 'SetUserObjectInformationA', 'BOOL',[
			["DWORD","hObj","in"],
			["DWORD","nIndex","in"],
			["PBLOB","pvInfo","in"],
			["DWORD","nLength","in"],
			])

		railgun.add_function( 'user32', 'SetUserObjectInformationW', 'BOOL',[
			["DWORD","hObj","in"],
			["DWORD","nIndex","in"],
			["PBLOB","pvInfo","in"],
			["DWORD","nLength","in"],
			])

		railgun.add_function( 'user32', 'SetUserObjectSecurity', 'BOOL',[
			["DWORD","hObj","in"],
			["PBLOB","pSIRequested","in"],
			["PBLOB","pSID","in"],
			])

		railgun.add_function( 'user32', 'SetWindowContextHelpId', 'BOOL',[
			["DWORD","param0","in"],
			["DWORD","param1","in"],
			])

		railgun.add_function( 'user32', 'SetWindowLongA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["DWORD","dwNewLong","in"],
			])

		railgun.add_function( 'user32', 'SetWindowLongW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["DWORD","dwNewLong","in"],
			])

		railgun.add_function( 'user32', 'SetWindowPlacement', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpwndpl","in"],
			])

		railgun.add_function( 'user32', 'SetWindowPos', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hWndInsertAfter","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'SetWindowRgn', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			["BOOL","bRedraw","in"],
			])

		railgun.add_function( 'user32', 'SetWindowTextA', 'BOOL',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'SetWindowTextW', 'BOOL',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'SetWindowWord', 'WORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["WORD","wNewWord","in"],
			])

		railgun.add_function( 'user32', 'SetWindowsHookA', 'DWORD',[
			["DWORD","nFilterType","in"],
			["DWORD","pfnFilterProc","in"],
			])

		railgun.add_function( 'user32', 'SetWindowsHookExA', 'DWORD',[
			["DWORD","idHook","in"],
			["DWORD","lpfn","in"],
			["DWORD","hmod","in"],
			["DWORD","dwThreadId","in"],
			])

		railgun.add_function( 'user32', 'SetWindowsHookExW', 'DWORD',[
			["DWORD","idHook","in"],
			["DWORD","lpfn","in"],
			["DWORD","hmod","in"],
			["DWORD","dwThreadId","in"],
			])

		railgun.add_function( 'user32', 'SetWindowsHookW', 'DWORD',[
			["DWORD","nFilterType","in"],
			["DWORD","pfnFilterProc","in"],
			])

		railgun.add_function( 'user32', 'ShowCaret', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'ShowCursor', 'DWORD',[
			["BOOL","bShow","in"],
			])

		railgun.add_function( 'user32', 'ShowOwnedPopups', 'BOOL',[
			["DWORD","hWnd","in"],
			["BOOL","fShow","in"],
			])

		railgun.add_function( 'user32', 'ShowScrollBar', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","wBar","in"],
			["BOOL","bShow","in"],
			])

		railgun.add_function( 'user32', 'ShowWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","nCmdShow","in"],
			])

		railgun.add_function( 'user32', 'ShowWindowAsync', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","nCmdShow","in"],
			])

		railgun.add_function( 'user32', 'SubtractRect', 'BOOL',[
			["PBLOB","lprcDst","out"],
			["PBLOB","lprcSrc1","in"],
			["PBLOB","lprcSrc2","in"],
			])

		railgun.add_function( 'user32', 'SwapMouseButton', 'BOOL',[
			["BOOL","fSwap","in"],
			])

		railgun.add_function( 'user32', 'SwitchDesktop', 'BOOL',[
			["DWORD","hDesktop","in"],
			])

		railgun.add_function( 'user32', 'SwitchToThisWindow', 'VOID',[
			["DWORD","hwnd","in"],
			["BOOL","fUnknown","in"],
			])

		railgun.add_function( 'user32', 'SystemParametersInfoA', 'BOOL',[
			["DWORD","uiAction","in"],
			["DWORD","uiParam","in"],
			["PBLOB","pvParam","inout"],
			["DWORD","fWinIni","in"],
			])

		railgun.add_function( 'user32', 'SystemParametersInfoW', 'BOOL',[
			["DWORD","uiAction","in"],
			["DWORD","uiParam","in"],
			["PBLOB","pvParam","inout"],
			["DWORD","fWinIni","in"],
			])

		railgun.add_function( 'user32', 'TabbedTextOutA', 'DWORD',[
			["DWORD","hdc","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["PCHAR","lpString","in"],
			["DWORD","chCount","in"],
			["DWORD","nTabPositions","in"],
			["PDWORD","lpnTabStopPositions","in"],
			["DWORD","nTabOrigin","in"],
			])

		railgun.add_function( 'user32', 'TabbedTextOutW', 'DWORD',[
			["DWORD","hdc","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["PWCHAR","lpString","in"],
			["DWORD","chCount","in"],
			["DWORD","nTabPositions","in"],
			["PDWORD","lpnTabStopPositions","in"],
			["DWORD","nTabOrigin","in"],
			])

		railgun.add_function( 'user32', 'TileWindows', 'WORD',[
			["DWORD","hwndParent","in"],
			["DWORD","wHow","in"],
			["PBLOB","lpRect","in"],
			["DWORD","cKids","in"],
			["PDWORD","lpKids","in"],
			])

		railgun.add_function( 'user32', 'ToAscii', 'DWORD',[
			["DWORD","uVirtKey","in"],
			["DWORD","uScanCode","in"],
			["PBLOB","lpKeyState","in"],
			["PBLOB","lpChar","out"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'ToAsciiEx', 'DWORD',[
			["DWORD","uVirtKey","in"],
			["DWORD","uScanCode","in"],
			["PBLOB","lpKeyState","in"],
			["PBLOB","lpChar","out"],
			["DWORD","uFlags","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'TrackMouseEvent', 'BOOL',[
			["PBLOB","lpEventTrack","inout"],
			])

		railgun.add_function( 'user32', 'TrackPopupMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uFlags","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["DWORD","nReserved","in"],
			["DWORD","hWnd","in"],
			["PBLOB","prcRect","in"],
			])

		railgun.add_function( 'user32', 'TranslateAcceleratorA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hAccTable","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'TranslateAcceleratorW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hAccTable","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'TranslateMDISysAccel', 'BOOL',[
			["DWORD","hWndClient","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'TranslateMessage', 'BOOL',[
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'UnhookWinEvent', 'BOOL',[
			["DWORD","hWinEventHook","in"],
			])

		railgun.add_function( 'user32', 'UnhookWindowsHook', 'BOOL',[
			["DWORD","nCode","in"],
			["DWORD","pfnFilterProc","in"],
			])

		railgun.add_function( 'user32', 'UnhookWindowsHookEx', 'BOOL',[
			["DWORD","hhk","in"],
			])

		railgun.add_function( 'user32', 'UnionRect', 'BOOL',[
			["PBLOB","lprcDst","out"],
			["PBLOB","lprcSrc1","in"],
			["PBLOB","lprcSrc2","in"],
			])

		railgun.add_function( 'user32', 'UnloadKeyboardLayout', 'BOOL',[
			["DWORD","hkl","in"],
			])

		railgun.add_function( 'user32', 'UnregisterClassA', 'BOOL',[
			["PCHAR","lpClassName","in"],
			["DWORD","hInstance","in"],
			])

		railgun.add_function( 'user32', 'UnregisterClassW', 'BOOL',[
			["PWCHAR","lpClassName","in"],
			["DWORD","hInstance","in"],
			])

		railgun.add_function( 'user32', 'UnregisterDeviceNotification', 'BOOL',[
			["DWORD","Handle","in"],
			])

		railgun.add_function( 'user32', 'UnregisterHotKey', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","id","in"],
			])

		railgun.add_function( 'user32', 'UpdateWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'UserHandleGrantAccess', 'BOOL',[
			["DWORD","hUserHandle","in"],
			["DWORD","hJob","in"],
			["BOOL","bGrant","in"],
			])

		railgun.add_function( 'user32', 'ValidateRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","in"],
			])

		railgun.add_function( 'user32', 'ValidateRgn', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			])

		railgun.add_function( 'user32', 'VkKeyScanA', 'WORD',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'VkKeyScanExA', 'WORD',[
			["BYTE","ch","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'VkKeyScanExW', 'WORD',[
			["WORD","ch","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'VkKeyScanW', 'WORD',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'WaitForInputIdle', 'DWORD',[
			["DWORD","hProcess","in"],
			["DWORD","dwMilliseconds","in"],
			])

		railgun.add_function( 'user32', 'WaitMessage', 'BOOL',[
			])

		railgun.add_function( 'user32', 'WinHelpA', 'BOOL',[
			["DWORD","hWndMain","in"],
			["PCHAR","lpszHelp","in"],
			["DWORD","uCommand","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'WinHelpW', 'BOOL',[
			["DWORD","hWndMain","in"],
			["PWCHAR","lpszHelp","in"],
			["DWORD","uCommand","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'WindowFromDC', 'DWORD',[
			["DWORD","hDC","in"],
			])

		railgun.add_function( 'user32', 'WindowFromPoint', 'DWORD',[
			["PBLOB","Point","in"],
			])

		railgun.add_function( 'user32', 'keybd_event', 'VOID',[
			["BYTE","bVk","in"],
			["BYTE","bScan","in"],
			["DWORD","dwFlags","in"],
			["PDWORD","dwExtraInfo","in"],
			])

		railgun.add_function( 'user32', 'mouse_event', 'VOID',[
			["DWORD","dwFlags","in"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			["DWORD","dwData","in"],
			["PDWORD","dwExtraInfo","in"],
			])


		railgun.add_dll('ws2_32','ws2_32')
		railgun.add_function( 'ws2_32', 'WSAAccept', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","addr","inout"],
			["PDWORD","addrlen","inout"],
			["PBLOB","lpfnCondition","in"],
			["PDWORD","dwCallbackData","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAAddressToStringA', 'DWORD',[
			["PBLOB","lpsaAddress","in"],
			["DWORD","dwAddressLength","in"],
			["PBLOB","lpProtocolInfo","in"],
			["PCHAR","lpszAddressString","inout"],
			["PDWORD","lpdwAddressStringLength","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAAddressToStringW', 'DWORD',[
			["PBLOB","lpsaAddress","in"],
			["DWORD","dwAddressLength","in"],
			["PBLOB","lpProtocolInfo","in"],
			["PWCHAR","lpszAddressString","inout"],
			["PDWORD","lpdwAddressStringLength","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAAsyncGetHostByAddr', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","wMsg","in"],
			["PCHAR","addr","in"],
			["DWORD","len","in"],
			["DWORD","type","in"],
			["PCHAR","buf","inout"],
			["DWORD","buflen","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAAsyncGetHostByName', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","wMsg","in"],
			["PCHAR","name","in"],
			["PCHAR","buf","inout"],
			["DWORD","buflen","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAAsyncGetProtoByName', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","wMsg","in"],
			["PCHAR","name","in"],
			["PCHAR","buf","inout"],
			["DWORD","buflen","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAAsyncGetProtoByNumber', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","wMsg","in"],
			["DWORD","number","in"],
			["PCHAR","buf","inout"],
			["DWORD","buflen","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAAsyncGetServByName', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","wMsg","in"],
			["PCHAR","name","in"],
			["PCHAR","proto","in"],
			["PCHAR","buf","inout"],
			["DWORD","buflen","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAAsyncGetServByPort', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","wMsg","in"],
			["DWORD","port","in"],
			["PCHAR","proto","in"],
			["PCHAR","buf","inout"],
			["DWORD","buflen","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAAsyncSelect', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","hWnd","in"],
			["DWORD","wMsg","in"],
			["DWORD","lEvent","in"],
			])

		railgun.add_function( 'ws2_32', 'WSACancelAsyncRequest', 'DWORD',[
			["DWORD","hAsyncTaskHandle","in"],
			])

		railgun.add_function( 'ws2_32', 'WSACancelBlockingCall', 'DWORD',[
			])

		railgun.add_function( 'ws2_32', 'WSACleanup', 'DWORD',[
			])

		railgun.add_function( 'ws2_32', 'WSACloseEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAConnect', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","name","in"],
			["DWORD","namelen","in"],
			["PBLOB","lpCallerData","in"],
			["PBLOB","lpCalleeData","inout"],
			["PBLOB","lpSQOS","in"],
			["PBLOB","lpGQOS","in"],
			])

		railgun.add_function( 'ws2_32', 'WSACreateEvent', 'DWORD',[
			])

		railgun.add_function( 'ws2_32', 'WSADuplicateSocketA', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","dwProcessId","in"],
			["PBLOB","lpProtocolInfo","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSADuplicateSocketW', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","dwProcessId","in"],
			["PBLOB","lpProtocolInfo","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAEnumNameSpaceProvidersA', 'DWORD',[
			["PDWORD","lpdwBufferLength","inout"],
			["PBLOB","lpnspBuffer","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAEnumNameSpaceProvidersW', 'DWORD',[
			["PDWORD","lpdwBufferLength","inout"],
			["PBLOB","lpnspBuffer","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAEnumNetworkEvents', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","hEventObject","in"],
			["PBLOB","lpNetworkEvents","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAEnumProtocolsA', 'DWORD',[
			["PDWORD","lpiProtocols","in"],
			["PBLOB","lpProtocolBuffer","inout"],
			["PDWORD","lpdwBufferLength","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAEnumProtocolsW', 'DWORD',[
			["PDWORD","lpiProtocols","in"],
			["PBLOB","lpProtocolBuffer","inout"],
			["PDWORD","lpdwBufferLength","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAEventSelect', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","hEventObject","in"],
			["DWORD","lNetworkEvents","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAGetLastError', 'DWORD',[
			])

		railgun.add_function( 'ws2_32', 'WSAGetOverlappedResult', 'BOOL',[
			["DWORD","s","in"],
			["PBLOB","lpOverlapped","in"],
			["PDWORD","lpcbTransfer","inout"],
			["BOOL","fWait","in"],
			["PDWORD","lpdwFlags","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAGetQOSByName', 'BOOL',[
			["DWORD","s","in"],
			["PBLOB","lpQOSName","in"],
			["PBLOB","lpQOS","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAGetServiceClassInfoA', 'DWORD',[
			["PBLOB","lpProviderId","in"],
			["PBLOB","lpServiceClassId","in"],
			["PDWORD","lpdwBufSize","inout"],
			["PBLOB","lpServiceClassInfo","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAGetServiceClassInfoW', 'DWORD',[
			["PBLOB","lpProviderId","in"],
			["PBLOB","lpServiceClassId","in"],
			["PDWORD","lpdwBufSize","inout"],
			["PBLOB","lpServiceClassInfo","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAGetServiceClassNameByClassIdA', 'DWORD',[
			["PBLOB","lpServiceClassId","in"],
			["PCHAR","lpszServiceClassName","inout"],
			["PDWORD","lpdwBufferLength","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAGetServiceClassNameByClassIdW', 'DWORD',[
			["PBLOB","lpServiceClassId","in"],
			["PWCHAR","lpszServiceClassName","inout"],
			["PDWORD","lpdwBufferLength","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAHtonl', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","hostlong","in"],
			["PDWORD","lpnetlong","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAHtons', 'DWORD',[
			["DWORD","s","in"],
			["WORD","hostshort","in"],
			["PBLOB","lpnetshort","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAInstallServiceClassA', 'DWORD',[
			["PBLOB","lpServiceClassInfo","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAInstallServiceClassW', 'DWORD',[
			["PBLOB","lpServiceClassInfo","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAIoctl', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","dwIoControlCode","in"],
			["PBLOB","lpvInBuffer","in"],
			["DWORD","cbInBuffer","in"],
			["PBLOB","lpvOutBuffer","inout"],
			["DWORD","cbOutBuffer","in"],
			["PDWORD","lpcbBytesReturned","inout"],
			["PBLOB","lpOverlapped","in"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAIsBlocking', 'BOOL',[
			])

		railgun.add_function( 'ws2_32', 'WSAJoinLeaf', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","name","in"],
			["DWORD","namelen","in"],
			["PBLOB","lpCallerData","in"],
			["PBLOB","lpCalleeData","inout"],
			["PBLOB","lpSQOS","in"],
			["PBLOB","lpGQOS","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'ws2_32', 'WSALookupServiceBeginA', 'DWORD',[
			["PBLOB","lpqsRestrictions","in"],
			["DWORD","dwControlFlags","in"],
			["PDWORD","lphLookup","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSALookupServiceBeginW', 'DWORD',[
			["PBLOB","lpqsRestrictions","in"],
			["DWORD","dwControlFlags","in"],
			["PDWORD","lphLookup","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSALookupServiceEnd', 'DWORD',[
			["DWORD","hLookup","in"],
			])

		railgun.add_function( 'ws2_32', 'WSALookupServiceNextA', 'DWORD',[
			["DWORD","hLookup","in"],
			["DWORD","dwControlFlags","in"],
			["PDWORD","lpdwBufferLength","inout"],
			["PBLOB","lpqsResults","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSALookupServiceNextW', 'DWORD',[
			["DWORD","hLookup","in"],
			["DWORD","dwControlFlags","in"],
			["PDWORD","lpdwBufferLength","inout"],
			["PBLOB","lpqsResults","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSANSPIoctl', 'DWORD',[
			["DWORD","hLookup","in"],
			["DWORD","dwControlCode","in"],
			["PBLOB","lpvInBuffer","in"],
			["DWORD","cbInBuffer","in"],
			["PBLOB","lpvOutBuffer","inout"],
			["DWORD","cbOutBuffer","in"],
			["PDWORD","lpcbBytesReturned","inout"],
			["PBLOB","lpCompletion","in"],
			])

		railgun.add_function( 'ws2_32', 'WSANtohl', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","netlong","in"],
			["PDWORD","lphostlong","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSANtohs', 'DWORD',[
			["DWORD","s","in"],
			["WORD","netshort","in"],
			["PBLOB","lphostshort","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAProviderConfigChange', 'DWORD',[
			["PDWORD","lpNotificationHandle","inout"],
			["PBLOB","lpOverlapped","in"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'ws2_32', 'WSARecv', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","lpBuffers","inout"],
			["DWORD","dwBufferCount","in"],
			["PDWORD","lpNumberOfBytesRecvd","inout"],
			["PDWORD","lpFlags","inout"],
			["PBLOB","lpOverlapped","in"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'ws2_32', 'WSARecvDisconnect', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","lpInboundDisconnectData","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSARecvFrom', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","lpBuffers","inout"],
			["DWORD","dwBufferCount","in"],
			["PDWORD","lpNumberOfBytesRecvd","inout"],
			["PDWORD","lpFlags","inout"],
			["PBLOB","lpFrom","inout"],
			["PDWORD","lpFromlen","inout"],
			["PBLOB","lpOverlapped","in"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'ws2_32', 'WSARemoveServiceClass', 'DWORD',[
			["PBLOB","lpServiceClassId","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAResetEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASend', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","lpBuffers","in"],
			["DWORD","dwBufferCount","in"],
			["PDWORD","lpNumberOfBytesSent","inout"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpOverlapped","in"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASendDisconnect', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","lpOutboundDisconnectData","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASendTo', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","lpBuffers","in"],
			["DWORD","dwBufferCount","in"],
			["PDWORD","lpNumberOfBytesSent","inout"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpTo","in"],
			["DWORD","iTolen","in"],
			["PBLOB","lpOverlapped","in"],
			["PBLOB","lpCompletionRoutine","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASetEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASetLastError', 'VOID',[
			["DWORD","iError","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASetServiceA', 'DWORD',[
			["PBLOB","lpqsRegInfo","in"],
			["PBLOB","essoperation","in"],
			["DWORD","dwControlFlags","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASetServiceW', 'DWORD',[
			["PBLOB","lpqsRegInfo","in"],
			["PBLOB","essoperation","in"],
			["DWORD","dwControlFlags","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASocketA', 'DWORD',[
			["DWORD","af","in"],
			["DWORD","type","in"],
			["DWORD","protocol","in"],
			["PBLOB","lpProtocolInfo","in"],
			["PBLOB","g","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'ws2_32', 'WSASocketW', 'DWORD',[
			["DWORD","af","in"],
			["DWORD","type","in"],
			["DWORD","protocol","in"],
			["PBLOB","lpProtocolInfo","in"],
			["PBLOB","g","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'ws2_32', 'WSAStartup', 'DWORD',[
			["WORD","wVersionRequested","in"],
			["PBLOB","lpWSAData","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAStringToAddressA', 'DWORD',[
			["PCHAR","AddressString","in"],
			["DWORD","AddressFamily","in"],
			["PBLOB","lpProtocolInfo","in"],
			["PBLOB","lpAddress","inout"],
			["PDWORD","lpAddressLength","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAStringToAddressW', 'DWORD',[
			["PWCHAR","AddressString","in"],
			["DWORD","AddressFamily","in"],
			["PBLOB","lpProtocolInfo","in"],
			["PBLOB","lpAddress","inout"],
			["PDWORD","lpAddressLength","inout"],
			])

		railgun.add_function( 'ws2_32', 'WSAUnhookBlockingHook', 'DWORD',[
			])

		railgun.add_function( 'ws2_32', 'WSAWaitForMultipleEvents', 'DWORD',[
			["DWORD","cEvents","in"],
			["PDWORD","lphEvents","in"],
			["BOOL","fWaitAll","in"],
			["DWORD","dwTimeout","in"],
			["BOOL","fAlertable","in"],
			])

		railgun.add_function( 'ws2_32', '__WSAFDIsSet', 'DWORD',[
			["DWORD","param0","in"],
			["PBLOB","param1","inout"],
			])

		railgun.add_function( 'ws2_32', 'accept', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","addr","inout"],
			["PDWORD","addrlen","inout"],
			])

		railgun.add_function( 'ws2_32', 'bind', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","name","in"],
			["DWORD","namelen","in"],
			])

		railgun.add_function( 'ws2_32', 'closesocket', 'DWORD',[
			["DWORD","s","in"],
			])

		railgun.add_function( 'ws2_32', 'connect', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","name","in"],
			["DWORD","namelen","in"],
			])

		railgun.add_function( 'ws2_32', 'gethostname', 'DWORD',[
			["PCHAR","name","inout"],
			["DWORD","namelen","in"],
			])

		railgun.add_function( 'ws2_32', 'getpeername', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","name","inout"],
			["PDWORD","namelen","inout"],
			])

		railgun.add_function( 'ws2_32', 'getsockname', 'DWORD',[
			["DWORD","s","in"],
			["PBLOB","name","inout"],
			["PDWORD","namelen","inout"],
			])

		railgun.add_function( 'ws2_32', 'getsockopt', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","level","in"],
			["DWORD","optname","in"],
			["PCHAR","optval","inout"],
			["PDWORD","optlen","inout"],
			])

		railgun.add_function( 'ws2_32', 'htonl', 'DWORD',[
			["DWORD","hostlong","in"],
			])

		railgun.add_function( 'ws2_32', 'htons', 'WORD',[
			["WORD","hostshort","in"],
			])

		railgun.add_function( 'ws2_32', 'inet_addr', 'DWORD',[
			["PCHAR","cp","in"],
			])

		railgun.add_function( 'ws2_32', 'ioctlsocket', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","cmd","in"],
			["PDWORD","argp","inout"],
			])

		railgun.add_function( 'ws2_32', 'listen', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","backlog","in"],
			])

		railgun.add_function( 'ws2_32', 'ntohl', 'DWORD',[
			["DWORD","netlong","in"],
			])

		railgun.add_function( 'ws2_32', 'ntohs', 'WORD',[
			["WORD","netshort","in"],
			])

		railgun.add_function( 'ws2_32', 'recv', 'DWORD',[
			["DWORD","s","in"],
			["PCHAR","buf","inout"],
			["DWORD","len","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'ws2_32', 'recvfrom', 'DWORD',[
			["DWORD","s","in"],
			["PCHAR","buf","inout"],
			["DWORD","len","in"],
			["DWORD","flags","in"],
			["PBLOB","from","inout"],
			["PDWORD","fromlen","inout"],
			])

		railgun.add_function( 'ws2_32', 'select', 'DWORD',[
			["DWORD","nfds","in"],
			["PBLOB","readfds","inout"],
			["PBLOB","writefds","inout"],
			["PBLOB","exceptfds","inout"],
			["PDWORD","timeout","in"],
			])

		railgun.add_function( 'ws2_32', 'send', 'DWORD',[
			["DWORD","s","in"],
			["PCHAR","buf","in"],
			["DWORD","len","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'ws2_32', 'sendto', 'DWORD',[
			["DWORD","s","in"],
			["PCHAR","buf","in"],
			["DWORD","len","in"],
			["DWORD","flags","in"],
			["PBLOB","to","in"],
			["DWORD","tolen","in"],
			])

		railgun.add_function( 'ws2_32', 'setsockopt', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","level","in"],
			["DWORD","optname","in"],
			["PCHAR","optval","in"],
			["DWORD","optlen","in"],
			])

		railgun.add_function( 'ws2_32', 'shutdown', 'DWORD',[
			["DWORD","s","in"],
			["DWORD","how","in"],
			])

		railgun.add_function( 'ws2_32', 'socket', 'DWORD',[
			["DWORD","af","in"],
			["DWORD","type","in"],
			["DWORD","protocol","in"],
			])


		railgun.add_dll('ntdll','ntdll')
		railgun.add_function( 'ntdll', 'NtClose', 'DWORD',[
			["DWORD","Handle","in"],
			])

		railgun.add_function( 'ntdll', 'NtCreateFile', 'DWORD',[
			["PDWORD","FileHandle","inout"],
			["DWORD","DesiredAccess","in"],
			["PBLOB","ObjectAttributes","in"],
			["PBLOB","IoStatusBlock","inout"],
			["PBLOB","AllocationSize","in"],
			["DWORD","FileAttributes","in"],
			["DWORD","ShareAccess","in"],
			["DWORD","CreateDisposition","in"],
			["DWORD","CreateOptions","in"],
			["PBLOB","EaBuffer","in"],
			["DWORD","EaLength","in"],
			])

		railgun.add_function( 'ntdll', 'NtDeviceIoControlFile', 'DWORD',[
			["DWORD","FileHandle","in"],
			["DWORD","Event","in"],
			["PBLOB","ApcRoutine","in"],
			["PBLOB","ApcContext","in"],
			["PBLOB","IoStatusBlock","inout"],
			["DWORD","IoControlCode","in"],
			["PBLOB","InputBuffer","in"],
			["DWORD","InputBufferLength","in"],
			["PBLOB","OutputBuffer","inout"],
			["DWORD","OutputBufferLength","in"],
			])

		railgun.add_function( 'ntdll', 'NtOpenFile', 'DWORD',[
			["PDWORD","FileHandle","inout"],
			["DWORD","DesiredAccess","in"],
			["PBLOB","ObjectAttributes","in"],
			["PBLOB","IoStatusBlock","inout"],
			["DWORD","ShareAccess","in"],
			["DWORD","OpenOptions","in"],
			])

		railgun.add_function( 'ntdll', 'NtQueryInformationProcess', 'DWORD',[
			["DWORD","ProcessHandle","in"],
			["DWORD","ProcessInformationClass","in"],
			["PBLOB","ProcessInformation","inout"],
			["DWORD","ProcessInformationLength","in"],
			["PDWORD","ReturnLength","inout"],
			])

		railgun.add_function( 'ntdll', 'NtQueryInformationThread', 'DWORD',[
			["DWORD","ThreadHandle","in"],
			["DWORD","ThreadInformationClass","in"],
			["PBLOB","ThreadInformation","inout"],
			["DWORD","ThreadInformationLength","in"],
			["PDWORD","ReturnLength","inout"],
			])

		railgun.add_function( 'ntdll', 'NtQuerySystemInformation', 'DWORD',[
			["DWORD","SystemInformationClass","in"],
			["PBLOB","SystemInformation","inout"],
			["DWORD","SystemInformationLength","in"],
			["PDWORD","ReturnLength","inout"],
			])

		railgun.add_function( 'ntdll', 'NtQuerySystemTime', 'DWORD',[
			["PBLOB","SystemTime","inout"],
			])

		railgun.add_function( 'ntdll', 'NtWaitForSingleObject', 'DWORD',[
			["DWORD","Handle","in"],
			["BOOL","Alertable","in"],
			["PBLOB","Timeout","in"],
			])

		railgun.add_function( 'ntdll', 'RtlCharToInteger', 'DWORD',[
			["PBLOB","String","inout"],
			["DWORD","Base","in"],
			["PDWORD","Value","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlConvertSidToUnicodeString', 'DWORD',[
			["PBLOB","UnicodeString","inout"],
			["PBLOB","Sid","inout"],
			["BOOL","AllocateDestinationString","in"],
			])

		railgun.add_function( 'ntdll', 'RtlFreeAnsiString', 'VOID',[
			["PBLOB","AnsiString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlFreeOemString', 'VOID',[
			["PBLOB","OemString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlFreeUnicodeString', 'VOID',[
			["PBLOB","UnicodeString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlInitAnsiString', 'VOID',[
			["PBLOB","DestinationString","inout"],
			["PBLOB","SourceString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlInitString', 'VOID',[
			["PBLOB","DestinationString","inout"],
			["PBLOB","SourceString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlLocalTimeToSystemTime', 'DWORD',[
			["PBLOB","LocalTime","in"],
			["PBLOB","SystemTime","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlNtStatusToDosError', 'DWORD',[
			["DWORD","Status","in"],
			])

		railgun.add_function( 'ntdll', 'RtlTimeToSecondsSince1970', 'BOOL',[
			["PBLOB","Time","inout"],
			["PDWORD","ElapsedSeconds","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlUniform', 'DWORD',[
			["PDWORD","Seed","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlUnwind', 'VOID',[
			["PBLOB","TargetFrame","in"],
			["PBLOB","TargetIp","in"],
			["PBLOB","ExceptionRecord","in"],
			["PBLOB","ReturnValue","in"],
			])

		railgun.add_function( 'kernel32', 'CreateToolhelp32Snapshot', 'DWORD',[
			["DWORD","dwFlags","in"],
			["DWORD","th32ProcessID","in"],
			])

		railgun.add_function( 'kernel32', 'Heap32First', 'BOOL',[
			["PBLOB","lphe","inout"],
			["DWORD","th32ProcessID","in"],
			["PDWORD","th32HeapID","inout"],
			])

		railgun.add_function( 'kernel32', 'Heap32ListFirst', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lphl","inout"],
			])

		railgun.add_function( 'kernel32', 'Heap32ListNext', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lphl","inout"],
			])

		railgun.add_function( 'kernel32', 'Heap32Next', 'BOOL',[
			["PBLOB","lphe","inout"],
			])

		railgun.add_function( 'kernel32', 'Module32First', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lpme","inout"],
			])

		railgun.add_function( 'kernel32', 'Module32FirstW', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lpme","inout"],
			])

		railgun.add_function( 'kernel32', 'Module32Next', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lpme","inout"],
			])

		railgun.add_function( 'kernel32', 'Module32NextW', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lpme","inout"],
			])

		railgun.add_function( 'kernel32', 'Process32First', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lppe","inout"],
			])

		railgun.add_function( 'kernel32', 'Process32FirstW', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lppe","inout"],
			])

		railgun.add_function( 'kernel32', 'Process32Next', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lppe","inout"],
			])

		railgun.add_function( 'kernel32', 'Process32NextW', 'BOOL',[
			["DWORD","hSnapshot","in"],
			["PBLOB","lppe","inout"],
                ])

		railgun.add_function( 'kernel32', 'Thread32First', 'BOOL',[
                                ["DWORD","hSnapshot","in"],
                                ["PBLOB","lpte","inout"],
			])

		railgun.add_function( 'kernel32', 'Thread32Next', 'BOOL',[
                                ["DWORD","hSnapshot","in"],
                                ["PBLOB","lpte","inout"],
			])

		railgun.add_function( 'kernel32', 'Toolhelp32ReadProcessMemory', 'BOOL',[
                                ["DWORD","th32ProcessID","in"],
                                ["PBLOB","lpBaseAddress","inout"],
                                ["PBLOB","lpBuffer","inout"],
                                ["DWORD","cbRead","in"],
                                ["PDWORD","lpNumberOfBytesRead","in"],
			])


		railgun.add_dll('Iphlpapi','Iphlpapi')
		railgun.add_function( 'Iphlpapi', 'CancelIPChangeNotify', 'BOOL',[
                                ["PBLOB","notifyOverlapped","in"],
			])

		railgun.add_function( 'Iphlpapi', 'CreateProxyArpEntry', 'DWORD',[
                                ["DWORD","dwAddress","in"],
                                ["DWORD","dwMask","in"],
                                ["DWORD","dwIfIndex","in"],
			])

		railgun.add_function( 'Iphlpapi', 'DeleteIPAddress', 'DWORD',[
                                ["DWORD","NTEContext","in"],
			])

		railgun.add_function( 'Iphlpapi', 'DeleteProxyArpEntry', 'DWORD',[
                                ["DWORD","dwAddress","in"],
                                ["DWORD","dwMask","in"],
                                ["DWORD","dwIfIndex","in"],
			])

		railgun.add_function( 'Iphlpapi', 'FlushIpNetTable', 'DWORD',[
                                ["DWORD","dwIfIndex","in"],
			])

		railgun.add_function( 'Iphlpapi', 'GetAdapterIndex', 'DWORD',[
                                ["PWCHAR","AdapterName","in"],
                                ["PDWORD","IfIndex","inout"],
			])

		railgun.add_function( 'Iphlpapi', 'GetBestInterface', 'DWORD',[
                                ["DWORD","dwDestAddr","in"],
                                ["PDWORD","pdwBestIfIndex","inout"],
			])

		railgun.add_function( 'Iphlpapi', 'GetBestInterfaceEx', 'DWORD',[
                                ["PBLOB","pDestAddr","in"],
                                ["PDWORD","pdwBestIfIndex","inout"],
			])

		railgun.add_function( 'Iphlpapi', 'GetFriendlyIfIndex', 'DWORD',[
                                ["DWORD","IfIndex","in"],
			])

		railgun.add_function( 'Iphlpapi', 'GetNumberOfInterfaces', 'DWORD',[
                                ["PDWORD","pdwNumIf","inout"],
			])

		railgun.add_function( 'Iphlpapi', 'GetRTTAndHopCount', 'BOOL',[
                                ["DWORD","DestIpAddress","in"],
                                ["PDWORD","HopCount","inout"],
                                ["DWORD","MaxHops","in"],
                                ["PDWORD","RTT","inout"],
			])

		railgun.add_function( 'Iphlpapi', 'NotifyAddrChange', 'DWORD',[
                                ["PDWORD","Handle","inout"],
                                ["PBLOB","overlapped","in"],
			])

		railgun.add_function( 'Iphlpapi', 'NotifyRouteChange', 'DWORD',[
                                ["PDWORD","Handle","inout"],
                                ["PBLOB","overlapped","in"],
			])

		railgun.add_function( 'Iphlpapi', 'SendARP', 'DWORD',[
                                ["DWORD","DestIP","in"],
                                ["DWORD","SrcIP","in"],
                                ["PDWORD","pMacAddr","inout"],
                                ["PDWORD","PhyAddrLen","inout"],
			])

		railgun.add_function( 'Iphlpapi', 'SetIpTTL', 'DWORD',[
                                ["DWORD","nTTL","in"],
			])
                railgun.kernel32.LoadLibraryA("Advapi32.dll")

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


	end # method
end #class
end # 5x module
end
end
end
end
