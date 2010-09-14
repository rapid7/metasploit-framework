module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_iphlpapi

	def self.add_imports(railgun)
		
		railgun.add_dll('iphlpapi')

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

	end
	
end

end; end; end; end; end; end; end


