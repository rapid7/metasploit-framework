module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_ws2_32

	def self.add_imports(railgun)
		
		railgun.add_dll('ws2_32')

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

	end
	
end

end; end; end; end; end; end; end


