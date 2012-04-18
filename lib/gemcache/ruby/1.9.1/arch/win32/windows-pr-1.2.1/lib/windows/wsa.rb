require 'windows/api'

module Windows
  module WSA
    API.auto_namespace = 'Windows::WSA'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    # Constants

    WSA_FLAG_OVERLAPPED             = 0x01
    WSA_FLAG_MULTIPOINT_C_ROOT      = 0x02
    WSA_FLAG_MULTIPOINT_C_LEAF      = 0x04
    WSA_FLAG_MULTIPOINT_D_ROOT      = 0x08
    WSA_FLAG_MULTIPOINT_D_LEAF      = 0x10
    WSA_FLAG_ACCESS_SYSTEM_SECURITY = 0x40
    WSA_FLAG_NO_HANDLE_INHERIT      = 0x80

    RNRSERVICE_REGISTER   = 0
    RNRSERVICE_DEREGISTER = 1
    RNRSERVICE_DELETE     = 2
    
    # Functions

    API.new('WSAAccept', 'LPPKP', 'L', 'ws2_32')
    API.new('WSAAddressToString', 'PLPPP', 'I', 'ws2_32')
    API.new('WSAAsyncGetHostByAddr', 'LISIIPI', 'L', 'ws2_32')
    API.new('WSAAsyncGetHostByName', 'LISPI', 'L', 'ws2_32')
    API.new('WSAAsyncGetProtoByName', 'LISPI', 'L', 'ws2_32')
    API.new('WSAAsyncGetProtoByNumber', 'LISPI', 'L', 'ws2_32')
    API.new('WSAAsyncGetServByName', 'LISSPI', 'L', 'ws2_32')
    API.new('WSAAsyncGetServByPort', 'LIISPI', 'L', 'ws2_32')
    API.new('WSAAsyncSelect', 'LLIL', 'I', 'ws2_32')
    API.new('WSACancelAsyncRequest', 'L', 'I', 'ws2_32')
    API.new('WSACleanup', 'V', 'I', 'ws2_32')
    API.new('WSACloseEvent', 'I', 'B', 'ws2_32')
    API.new('WSAConnect', 'LPIPPPP', 'I', 'ws2_32')
    API.new('WSACreateEvent', 'V', 'L', 'ws2_32')
    API.new('WSADuplicateSocket', 'LLP', 'I', 'ws2_32')
    API.new('WSAEnumNetworkEvents', 'LLP', 'I', 'ws2_32')
    API.new('WSAEnumProtocols', 'PPP', 'I', 'ws2_32')
    API.new('WSAEventSelect', 'LLL', 'I', 'ws2_32')
    API.new('WSAGetLastError', 'V', 'I', 'ws2_32')
    API.new('WSAGetOverlappedResult', 'LPPIP', 'B', 'ws2_32')
    API.new('WSAGetQOSByName', 'LPP', 'B', 'ws2_32')
    API.new('WSAGetServiceClassInfo', 'PPPP', 'I', 'ws2_32')
    API.new('WSAGetServiceClassNameByClassId', 'PPP', 'I', 'ws2_32')
    API.new('WSAHtonl', 'LLP', 'I', 'ws2_32')
    API.new('WSAHtons', 'LIP', 'I', 'ws2_32')
    API.new('WSAInstallServiceClass', 'P', 'I', 'ws2_32')
    API.new('WSAIoctl', 'LLPLPLPPP', 'I', 'ws2_32')
    API.new('WSAJoinLeaf', 'LPIPPPPL', 'L', 'ws2_32')
    API.new('WSALookupServiceBegin', 'PLP', 'I', 'ws2_32')
    API.new('WSALookupServiceEnd', 'L', 'I', 'ws2_32')
    API.new('WSALookupServiceNext', 'LLPP', 'I', 'ws2_32')
    API.new('WSANtohl', 'LLP', 'I', 'ws2_32')
    API.new('WSANtohs', 'LIP', 'I', 'ws2_32')
    API.new('WSAProviderConfigChange', 'PPP', 'I', 'ws2_32')
    API.new('WSARecv', 'LPLPPPP', 'I', 'ws2_32')
    API.new('WSARecvDisconnect', 'LP', 'I', 'ws2_32')
    API.new('WSARecvEx', 'LPIP', 'I', 'mswsock')
    API.new('WSARecvFrom', 'LPLPPPPPP', 'I', 'ws2_32')
    API.new('WSARemoveServiceClass', 'P', 'I', 'ws2_32')
    API.new('WSAResetEvent', 'L', 'B', 'ws2_32')
    API.new('WSASend', 'LPLPLPP', 'I', 'ws2_32')
    API.new('WSASendDisconnect', 'LP', 'I', 'ws2_32')
    API.new('WSASendTo', 'LPLPLPIPP', 'I', 'ws2_32')
    API.new('WSASetEvent', 'L', 'B', 'ws2_32')
    API.new('WSASetLastError', 'I', 'V', 'ws2_32')
    API.new('WSASetService', 'PIL', 'I', 'ws2_32')
    API.new('WSAStartup', 'LP', 'I', 'ws2_32')
    API.new('WSASocket', 'IIIPLL', 'L', 'ws2_32')
    API.new('WSAStringToAddress', 'PIPPP', 'I', 'ws2_32')
    API.new('WSAWaitForMultipleEvents', 'LPILI', 'L', 'ws2_32')

    begin
      API.new('WSAConnectByList', 'LPPPPPPP', 'B', 'ws2_32')
      API.new('WSAConnectByName', 'LPPPPPPP', 'B', 'ws2_32')
      API.new('WSADeleteSocketPeerTargetName', 'LPLPP', 'L', 'fwpuclnt')
      API.new('WSAEnumNameSpaceProvidersEx', 'PP', 'I', 'ws2_32')
      API.new('WSAPoll', 'PLI', 'I', 'ws2_32')
      API.new('WSAQuerySocketSecurity', 'LPLPPPP', 'I', 'fwpuclnt')
      API.new('WSARevertImpersonation', 'V', 'I', 'fwpuclnt')
      API.new('WSASendMsg', 'LPLPPP', 'I', 'ws2_32')
      API.new('WSASetSocketPeerTargetName', 'LPLPP', 'I', 'fwpuclnt')
      API.new('WSASetSocketSecurity', 'LPLPP', 'I', 'fwpuclnt')
    rescue Win32::API::LoadLibraryError
      # Vista or later
    end

    begin
      API.new('WSAEnumNameSpaceProviders', 'PP', 'I', 'ws2_32')
      API.new('WSAImpersonateSocketPeer', 'LPL', 'I', 'fwpuclnt')
      API.new('WSANSPIoctl', 'LLPLPLPP', 'I', 'ws2_32')
    rescue Win32::API::LoadLibraryError
      # XP or later
    end
  end
end
