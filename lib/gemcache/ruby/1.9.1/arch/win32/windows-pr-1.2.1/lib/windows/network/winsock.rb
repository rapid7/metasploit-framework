require 'windows/api'

module Windows
  module Network
    module Winsock
      API.auto_namespace = 'Windows::Network::Winsock'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      # Namespace constants
      NS_DEFAULT     = 0
      NS_SAP         = 1
      NS_NDS         = 2
      NS_PEER_BROWSE = 3
      NS_TCPIP_LOCAL = 10
      NS_TCPIP_HOSTS = 11
      NS_DNS         = 12
      NS_NETBT       = 13
      NS_WINS        = 14
      NS_NBP         = 20
      NS_MS          = 30
      NS_STDA        = 31
      NS_NTDS        = 32
      NS_X500        = 40
      NS_NIS         = 41
      NS_VNS         = 50

      # Resolution flags
      RES_SOFT_SEARCH   = 0x00000001
      RES_FIND_MULTIPLE = 0x00000002
      RES_SERVICE       = 0x00000004

      API.new('accept', 'LPP', 'L', 'ws2_32')
      API.new('AcceptEx', 'LLPLLLPP', 'B', 'mswsock')
      API.new('bind', 'LPL', 'I', 'ws2_32')
      API.new('closesocket', 'L', 'I', 'ws2_32')
      API.new('connect', 'LPI', 'I', 'ws2_32')
      API.new('EnumProtocols', 'PPP', 'I', 'mswsock')
      API.new('GetAcceptExSockaddrs', 'PLLLPPPP', 'V', 'mswsock')
      API.new('GetAddressByName', 'LPPPLPPPPP', 'V', 'mswsock')
      API.new('gethostbyaddr', 'PII', 'L', 'ws2_32')
      API.new('gethostbyname', 'P', 'L', 'ws2_32')
      API.new('gethostname', 'PI', 'I', 'ws2_32')
      API.new('GetNameByType', 'PPL', 'I', 'mswsock')
      API.new('getpeername', 'LPP', 'I', 'ws2_32')
      API.new('getprotobyname', 'P', 'L', 'ws2_32')
      API.new('getprotobynumber', 'L', 'L', 'ws2_32')
      API.new('getservbyname', 'PP', 'L', 'ws2_32')
      API.new('getservbyport', 'IP', 'L', 'ws2_32')
      API.new('GetService', 'LPPLPPP', 'I', 'mswsock')
      API.new('getsockname', 'LPP', 'I', 'ws2_32')
      API.new('getsockopt', 'LIIPP', 'I', 'ws2_32')
      API.new('GetTypeByName', 'PP', 'I', 'mswsock')
      API.new('htonl', 'L', 'L', 'ws2_32')
      API.new('htons', 'I', 'I', 'ws2_32')
      API.new('inet_addr', 'P', 'L', 'ws2_32')
      API.new('inet_ntoa', 'P', 'P', 'ws2_32')
      API.new('ioctlsocket', 'LLP', 'I', 'ws2_32')
      API.new('listen', 'LI', 'I', 'ws2_32')
      API.new('ntohl', 'L', 'L', 'ws2_32')
      API.new('ntohs', 'I', 'I', 'ws2_32')
      API.new('recv', 'LPII', 'I', 'ws2_32')
      API.new('recvfrom', 'LPIIPP', 'I', 'ws2_32')
      API.new('select', 'IPPPP', 'I', 'ws2_32')
      API.new('send', 'LPII', 'I', 'ws2_32')
      API.new('sendto', 'LPIIPI', 'I', 'ws2_32')
      API.new('SetService', 'LLLPPP', 'I', 'mswsock')
      API.new('setsockopt', 'LIIPI', 'I', 'ws2_32')
      API.new('shutdown', 'LI', 'I', 'ws2_32')
      API.new('socket', 'III', 'L', 'ws2_32')
      API.new('TransmitFile', 'LLLLPPL', 'B', 'mswsock')

      API.new('WSAAccept', 'PPPKL', 'I', 'ws2_32')
      API.new('WSAAddressToString', 'PLPPP', 'I', 'ws2_32')
      API.new('WSAAsyncGetHostByAddr', 'LIPIIPI', 'L', 'ws2_32')
      API.new('WSAAsyncGetHostByName', 'LIPPI', 'L', 'ws2_32')
      API.new('WSAAsyncGetProtoByName', 'LIPPI', 'L', 'ws2_32')
      API.new('WSAAsyncGetServByName', 'LIPPPL', 'L', 'ws2_32')
      API.new('WSAAsyncGetServByPort', 'LIIPPI', 'L', 'ws2_32')
      API.new('WSAAsyncSelect', 'PLIL', 'I', 'ws2_32')
      API.new('WSACleanup', 'V', 'I', 'ws2_32')
      API.new('WSACloseEvent', 'L', 'B', 'ws2_32')
      API.new('WSAConnect', 'LPIPPPP', 'I', 'ws2_32')
      API.new('WSACreateEvent', 'V', 'L', 'ws2_32')
      API.new('WSADuplicateSocket', 'LLP', 'I', 'ws2_32')
      API.new('WSAEnumNameSpaceProviders', 'PP', 'I', 'ws2_32')
      API.new('WSAEnumNetworkEvents', 'LLP', 'I', 'ws2_32')
      API.new('WSAEnumProtocols', 'PPP', 'I', 'ws2_32')
      API.new('WSAEventSelect', 'LLL', 'I', 'ws2_32')
      API.new('WSAGetLastError', 'V', 'I', 'ws2_32')
      API.new('WSAIoctl', 'LLPLPLPPP', 'I', 'ws2_32')
      API.new('WSARecv', 'LPLPPPP', 'I', 'ws2_32')
      API.new('WSASocket', 'IIIPIL', 'L', 'ws2_32')
      API.new('WSAStartup', 'IP', 'I', 'ws2_32')
      API.new('WSAStringToAddress', 'PIPPP', 'I', 'ws2_32')
      API.new('WSAWaitForMultipleEvents', 'LPBLB', 'L', 'ws2_32')

      # XP or later
      begin
        API.new('ConnectEx', 'LPIPLPP', 'B', 'mswsock')
        API.new('DisconnectEx', 'LPLL', 'B', 'mswsock')
        API.new('freeaddrinfo', 'P', 'V', 'ws2_32')
        API.new('FreeAddrInfoW', 'P', 'V', 'ws2_32')
        API.new('getaddrinfo', 'PPPP', 'I', 'ws2_32')
        API.new('GetAddrInfoW', 'PPPP', 'I', 'mswsock')
        API.new('getnameinfo', 'PLPLPLI', 'I', 'ws2_32')
        API.new('GetNameInfoW', 'PLPLPLI', 'I', 'ws2_32')
      rescue Win32::API::LoadLibraryError
        # Do nothing, not supported on your platform.
      end

      # Vista or later
      begin
        API.new('FreeAddrInfoEx', 'P', 'V', 'ws2_32')
        API.new('GetAddrInfoEx', 'PPLPPPPPPP', 'I', 'ws2_32')
        API.new('WSAConnectByList', 'LPPPPPPP', 'B', 'ws2_32')
        API.new('WSAConnectByName', 'LPPPPPPP', 'B', 'ws2_32')
        API.new('WSADeleteSocketPeerTargetName', 'LPPPP', 'I', 'ws2_32')
        API.new('WSAPoll', 'PLI', 'I', 'ws2_32')
      rescue Win32::API::LoadLibraryError
        # Do nothing, not supported on your platform.
      end
    end
  end
end
