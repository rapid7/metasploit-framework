# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_ws2_32

  def self.create_dll(dll_path = 'ws2_32')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function('getaddrinfo', 'DWORD',[
      ["PCHAR","pNodeName","in"],
      ["PCHAR","pServiceName","in"],
      ["PDWORD","pHints","in"],
      ["PDWORD","ppResult","out"]
      ])

    dll.add_function('gethostbyaddr', 'DWORD', [
      ['PCHAR', 'addr', 'in'],
      ['DWORD','len','in'],
      ['DWORD','type','in']
      ])

    dll.add_function('WSAAccept', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","addr","inout"],
      ["PDWORD","addrlen","inout"],
      ["PBLOB","lpfnCondition","in"],
      ["PDWORD","dwCallbackData","in"],
      ])

    dll.add_function('WSAAddressToStringA', 'DWORD',[
      ["PBLOB","lpsaAddress","in"],
      ["DWORD","dwAddressLength","in"],
      ["PBLOB","lpProtocolInfo","in"],
      ["PCHAR","lpszAddressString","inout"],
      ["PDWORD","lpdwAddressStringLength","inout"],
      ])

    dll.add_function('WSAAddressToStringW', 'DWORD',[
      ["PBLOB","lpsaAddress","in"],
      ["DWORD","dwAddressLength","in"],
      ["PBLOB","lpProtocolInfo","in"],
      ["PWCHAR","lpszAddressString","inout"],
      ["PDWORD","lpdwAddressStringLength","inout"],
      ])

    dll.add_function('WSAAsyncGetHostByAddr', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","wMsg","in"],
      ["PCHAR","addr","in"],
      ["DWORD","len","in"],
      ["DWORD","type","in"],
      ["PCHAR","buf","inout"],
      ["DWORD","buflen","in"],
      ])

    dll.add_function('WSAAsyncGetHostByName', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","wMsg","in"],
      ["PCHAR","name","in"],
      ["PCHAR","buf","inout"],
      ["DWORD","buflen","in"],
      ])

    dll.add_function('WSAAsyncGetProtoByName', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","wMsg","in"],
      ["PCHAR","name","in"],
      ["PCHAR","buf","inout"],
      ["DWORD","buflen","in"],
      ])

    dll.add_function('WSAAsyncGetProtoByNumber', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","wMsg","in"],
      ["DWORD","number","in"],
      ["PCHAR","buf","inout"],
      ["DWORD","buflen","in"],
      ])

    dll.add_function('WSAAsyncGetServByName', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","wMsg","in"],
      ["PCHAR","name","in"],
      ["PCHAR","proto","in"],
      ["PCHAR","buf","inout"],
      ["DWORD","buflen","in"],
      ])

    dll.add_function('WSAAsyncGetServByPort', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","wMsg","in"],
      ["DWORD","port","in"],
      ["PCHAR","proto","in"],
      ["PCHAR","buf","inout"],
      ["DWORD","buflen","in"],
      ])

    dll.add_function('WSAAsyncSelect', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","hWnd","in"],
      ["DWORD","wMsg","in"],
      ["DWORD","lEvent","in"],
      ])

    dll.add_function('WSACancelAsyncRequest', 'DWORD',[
      ["DWORD","hAsyncTaskHandle","in"],
      ])

    dll.add_function('WSACancelBlockingCall', 'DWORD',[
      ])

    dll.add_function('WSACleanup', 'DWORD',[
      ])

    dll.add_function('WSACloseEvent', 'BOOL',[
      ["DWORD","hEvent","in"],
      ])

    dll.add_function('WSAConnect', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","name","in"],
      ["DWORD","namelen","in"],
      ["PBLOB","lpCallerData","in"],
      ["PBLOB","lpCalleeData","inout"],
      ["PBLOB","lpSQOS","in"],
      ["PBLOB","lpGQOS","in"],
      ])

    dll.add_function('WSACreateEvent', 'DWORD',[
      ])

    dll.add_function('WSADuplicateSocketA', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","dwProcessId","in"],
      ["PBLOB","lpProtocolInfo","inout"],
      ])

    dll.add_function('WSADuplicateSocketW', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","dwProcessId","in"],
      ["PBLOB","lpProtocolInfo","inout"],
      ])

    dll.add_function('WSAEnumNameSpaceProvidersA', 'DWORD',[
      ["PDWORD","lpdwBufferLength","inout"],
      ["PBLOB","lpnspBuffer","inout"],
      ])

    dll.add_function('WSAEnumNameSpaceProvidersW', 'DWORD',[
      ["PDWORD","lpdwBufferLength","inout"],
      ["PBLOB","lpnspBuffer","inout"],
      ])

    dll.add_function('WSAEnumNetworkEvents', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","hEventObject","in"],
      ["PBLOB","lpNetworkEvents","inout"],
      ])

    dll.add_function('WSAEnumProtocolsA', 'DWORD',[
      ["PDWORD","lpiProtocols","in"],
      ["PBLOB","lpProtocolBuffer","inout"],
      ["PDWORD","lpdwBufferLength","inout"],
      ])

    dll.add_function('WSAEnumProtocolsW', 'DWORD',[
      ["PDWORD","lpiProtocols","in"],
      ["PBLOB","lpProtocolBuffer","inout"],
      ["PDWORD","lpdwBufferLength","inout"],
      ])

    dll.add_function('WSAEventSelect', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","hEventObject","in"],
      ["DWORD","lNetworkEvents","in"],
      ])

    dll.add_function('WSAGetLastError', 'DWORD',[
      ])

    dll.add_function('WSAGetOverlappedResult', 'BOOL',[
      ["DWORD","s","in"],
      ["PBLOB","lpOverlapped","in"],
      ["PDWORD","lpcbTransfer","inout"],
      ["BOOL","fWait","in"],
      ["PDWORD","lpdwFlags","inout"],
      ])

    dll.add_function('WSAGetQOSByName', 'BOOL',[
      ["DWORD","s","in"],
      ["PBLOB","lpQOSName","in"],
      ["PBLOB","lpQOS","inout"],
      ])

    dll.add_function('WSAGetServiceClassInfoA', 'DWORD',[
      ["PBLOB","lpProviderId","in"],
      ["PBLOB","lpServiceClassId","in"],
      ["PDWORD","lpdwBufSize","inout"],
      ["PBLOB","lpServiceClassInfo","inout"],
      ])

    dll.add_function('WSAGetServiceClassInfoW', 'DWORD',[
      ["PBLOB","lpProviderId","in"],
      ["PBLOB","lpServiceClassId","in"],
      ["PDWORD","lpdwBufSize","inout"],
      ["PBLOB","lpServiceClassInfo","inout"],
      ])

    dll.add_function('WSAGetServiceClassNameByClassIdA', 'DWORD',[
      ["PBLOB","lpServiceClassId","in"],
      ["PCHAR","lpszServiceClassName","inout"],
      ["PDWORD","lpdwBufferLength","inout"],
      ])

    dll.add_function('WSAGetServiceClassNameByClassIdW', 'DWORD',[
      ["PBLOB","lpServiceClassId","in"],
      ["PWCHAR","lpszServiceClassName","inout"],
      ["PDWORD","lpdwBufferLength","inout"],
      ])

    dll.add_function('WSAHtonl', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","hostlong","in"],
      ["PDWORD","lpnetlong","inout"],
      ])

    dll.add_function('WSAHtons', 'DWORD',[
      ["DWORD","s","in"],
      ["WORD","hostshort","in"],
      ["PBLOB","lpnetshort","inout"],
      ])

    dll.add_function('WSAInstallServiceClassA', 'DWORD',[
      ["PBLOB","lpServiceClassInfo","in"],
      ])

    dll.add_function('WSAInstallServiceClassW', 'DWORD',[
      ["PBLOB","lpServiceClassInfo","in"],
      ])

    dll.add_function('WSAIoctl', 'DWORD',[
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

    dll.add_function('WSAIsBlocking', 'BOOL',[
      ])

    dll.add_function('WSAJoinLeaf', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","name","in"],
      ["DWORD","namelen","in"],
      ["PBLOB","lpCallerData","in"],
      ["PBLOB","lpCalleeData","inout"],
      ["PBLOB","lpSQOS","in"],
      ["PBLOB","lpGQOS","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('WSALookupServiceBeginA', 'DWORD',[
      ["PBLOB","lpqsRestrictions","in"],
      ["DWORD","dwControlFlags","in"],
      ["PDWORD","lphLookup","inout"],
      ])

    dll.add_function('WSALookupServiceBeginW', 'DWORD',[
      ["PBLOB","lpqsRestrictions","in"],
      ["DWORD","dwControlFlags","in"],
      ["PDWORD","lphLookup","inout"],
      ])

    dll.add_function('WSALookupServiceEnd', 'DWORD',[
      ["DWORD","hLookup","in"],
      ])

    dll.add_function('WSALookupServiceNextA', 'DWORD',[
      ["DWORD","hLookup","in"],
      ["DWORD","dwControlFlags","in"],
      ["PDWORD","lpdwBufferLength","inout"],
      ["PBLOB","lpqsResults","inout"],
      ])

    dll.add_function('WSALookupServiceNextW', 'DWORD',[
      ["DWORD","hLookup","in"],
      ["DWORD","dwControlFlags","in"],
      ["PDWORD","lpdwBufferLength","inout"],
      ["PBLOB","lpqsResults","inout"],
      ])

    dll.add_function('WSANSPIoctl', 'DWORD',[
      ["DWORD","hLookup","in"],
      ["DWORD","dwControlCode","in"],
      ["PBLOB","lpvInBuffer","in"],
      ["DWORD","cbInBuffer","in"],
      ["PBLOB","lpvOutBuffer","inout"],
      ["DWORD","cbOutBuffer","in"],
      ["PDWORD","lpcbBytesReturned","inout"],
      ["PBLOB","lpCompletion","in"],
      ])

    dll.add_function('WSANtohl', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","netlong","in"],
      ["PDWORD","lphostlong","inout"],
      ])

    dll.add_function('WSANtohs', 'DWORD',[
      ["DWORD","s","in"],
      ["WORD","netshort","in"],
      ["PBLOB","lphostshort","inout"],
      ])

    dll.add_function('WSAProviderConfigChange', 'DWORD',[
      ["PDWORD","lpNotificationHandle","inout"],
      ["PBLOB","lpOverlapped","in"],
      ["PBLOB","lpCompletionRoutine","in"],
      ])

    dll.add_function('WSARecv', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","lpBuffers","inout"],
      ["DWORD","dwBufferCount","in"],
      ["PDWORD","lpNumberOfBytesRecvd","inout"],
      ["PDWORD","lpFlags","inout"],
      ["PBLOB","lpOverlapped","in"],
      ["PBLOB","lpCompletionRoutine","in"],
      ])

    dll.add_function('WSARecvDisconnect', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","lpInboundDisconnectData","inout"],
      ])

    dll.add_function('WSARecvFrom', 'DWORD',[
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

    dll.add_function('WSARemoveServiceClass', 'DWORD',[
      ["PBLOB","lpServiceClassId","in"],
      ])

    dll.add_function('WSAResetEvent', 'BOOL',[
      ["DWORD","hEvent","in"],
      ])

    dll.add_function('WSASend', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","lpBuffers","in"],
      ["DWORD","dwBufferCount","in"],
      ["PDWORD","lpNumberOfBytesSent","inout"],
      ["DWORD","dwFlags","in"],
      ["PBLOB","lpOverlapped","in"],
      ["PBLOB","lpCompletionRoutine","in"],
      ])

    dll.add_function('WSASendDisconnect', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","lpOutboundDisconnectData","in"],
      ])

    dll.add_function('WSASendTo', 'DWORD',[
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

    dll.add_function('WSASetEvent', 'BOOL',[
      ["DWORD","hEvent","in"],
      ])

    dll.add_function('WSASetLastError', 'VOID',[
      ["DWORD","iError","in"],
      ])

    dll.add_function('WSASetServiceA', 'DWORD',[
      ["PBLOB","lpqsRegInfo","in"],
      ["PBLOB","essoperation","in"],
      ["DWORD","dwControlFlags","in"],
      ])

    dll.add_function('WSASetServiceW', 'DWORD',[
      ["PBLOB","lpqsRegInfo","in"],
      ["PBLOB","essoperation","in"],
      ["DWORD","dwControlFlags","in"],
      ])

    dll.add_function('WSASocketA', 'DWORD',[
      ["DWORD","af","in"],
      ["DWORD","type","in"],
      ["DWORD","protocol","in"],
      ["PBLOB","lpProtocolInfo","in"],
      ["PBLOB","g","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('WSASocketW', 'DWORD',[
      ["DWORD","af","in"],
      ["DWORD","type","in"],
      ["DWORD","protocol","in"],
      ["PBLOB","lpProtocolInfo","in"],
      ["PBLOB","g","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('WSAStartup', 'DWORD',[
      ["WORD","wVersionRequested","in"],
      ["PBLOB","lpWSAData","inout"],
      ])

    dll.add_function('WSAStringToAddressA', 'DWORD',[
      ["PCHAR","AddressString","in"],
      ["DWORD","AddressFamily","in"],
      ["PBLOB","lpProtocolInfo","in"],
      ["PBLOB","lpAddress","inout"],
      ["PDWORD","lpAddressLength","inout"],
      ])

    dll.add_function('WSAStringToAddressW', 'DWORD',[
      ["PWCHAR","AddressString","in"],
      ["DWORD","AddressFamily","in"],
      ["PBLOB","lpProtocolInfo","in"],
      ["PBLOB","lpAddress","inout"],
      ["PDWORD","lpAddressLength","inout"],
      ])

    dll.add_function('WSAUnhookBlockingHook', 'DWORD',[
      ])

    dll.add_function('WSAWaitForMultipleEvents', 'DWORD',[
      ["DWORD","cEvents","in"],
      ["PDWORD","lphEvents","in"],
      ["BOOL","fWaitAll","in"],
      ["DWORD","dwTimeout","in"],
      ["BOOL","fAlertable","in"],
      ])

    dll.add_function('__WSAFDIsSet', 'DWORD',[
      ["DWORD","param0","in"],
      ["PBLOB","param1","inout"],
      ])

    dll.add_function('accept', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","addr","inout"],
      ["PDWORD","addrlen","inout"],
      ])

    dll.add_function('bind', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","name","in"],
      ["DWORD","namelen","in"],
      ])

    dll.add_function('closesocket', 'DWORD',[
      ["DWORD","s","in"],
      ])

    dll.add_function('connect', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","name","in"],
      ["DWORD","namelen","in"],
      ])

    dll.add_function('gethostname', 'DWORD',[
      ["PCHAR","name","inout"],
      ["DWORD","namelen","in"],
      ])

    dll.add_function('getpeername', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","name","inout"],
      ["PDWORD","namelen","inout"],
      ])

    dll.add_function('getsockname', 'DWORD',[
      ["DWORD","s","in"],
      ["PBLOB","name","inout"],
      ["PDWORD","namelen","inout"],
      ])

    dll.add_function('getsockopt', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","level","in"],
      ["DWORD","optname","in"],
      ["PCHAR","optval","inout"],
      ["PDWORD","optlen","inout"],
      ])

    dll.add_function('htonl', 'DWORD',[
      ["DWORD","hostlong","in"],
      ])

    dll.add_function('htons', 'WORD',[
      ["WORD","hostshort","in"],
      ])

    dll.add_function('inet_addr', 'DWORD',[
      ["PCHAR","cp","in"],
      ])

    dll.add_function('ioctlsocket', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","cmd","in"],
      ["PDWORD","argp","inout"],
      ])

    dll.add_function('listen', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","backlog","in"],
      ])

    dll.add_function('ntohl', 'DWORD',[
      ["DWORD","netlong","in"],
      ])

    dll.add_function('ntohs', 'WORD',[
      ["WORD","netshort","in"],
      ])

    dll.add_function('recv', 'DWORD',[
      ["DWORD","s","in"],
      ["PCHAR","buf","inout"],
      ["DWORD","len","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('recvfrom', 'DWORD',[
      ["DWORD","s","in"],
      ["PCHAR","buf","inout"],
      ["DWORD","len","in"],
      ["DWORD","flags","in"],
      ["PBLOB","from","inout"],
      ["PDWORD","fromlen","inout"],
      ])

    dll.add_function('select', 'DWORD',[
      ["DWORD","nfds","in"],
      ["PBLOB","readfds","inout"],
      ["PBLOB","writefds","inout"],
      ["PBLOB","exceptfds","inout"],
      ["PDWORD","timeout","in"],
      ])

    dll.add_function('send', 'DWORD',[
      ["DWORD","s","in"],
      ["PCHAR","buf","in"],
      ["DWORD","len","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('sendto', 'DWORD',[
      ["DWORD","s","in"],
      ["PCHAR","buf","in"],
      ["DWORD","len","in"],
      ["DWORD","flags","in"],
      ["PBLOB","to","in"],
      ["DWORD","tolen","in"],
      ])

    dll.add_function('setsockopt', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","level","in"],
      ["DWORD","optname","in"],
      ["PCHAR","optval","in"],
      ["DWORD","optlen","in"],
      ])

    dll.add_function('shutdown', 'DWORD',[
      ["DWORD","s","in"],
      ["DWORD","how","in"],
      ])

    dll.add_function('socket', 'DWORD',[
      ["DWORD","af","in"],
      ["DWORD","type","in"],
      ["DWORD","protocol","in"],
      ])

    return dll
  end

end

end; end; end; end; end; end; end


