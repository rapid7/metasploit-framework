require 'windows/api'

module Windows
  module Socket
    API.auto_namespace = 'Windows::Socket'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    # Constants

    IPPROTO_IP            = 0         # dummy for IP
    IPPROTO_ICMP          = 1         # control message protocol
    IPPROTO_IGMP          = 2         # group management protocol
    IPPROTO_GGP           = 3         # gateway^2 (deprecated)
    IPPROTO_TCP           = 6         # tcp
    IPPROTO_PUP           = 12        # pup
    IPPROTO_UDP           = 17        # user datagram protocol
    IPPROTO_IDP           = 22        # xns idp
    IPPROTO_ND            = 77        # UNOFFICIAL net disk proto
    IPPROTO_RAW           = 255       # raw IP packet
    IPPROTO_MAX           = 256

    NSPROTO_IPX   = 1000
    NSPROTO_SPX   = 1256
    NSPROTO_SPXII = 1257

    # Functions

    API.new('accept', 'LPP', 'L', 'ws2_32')
    API.new('AcceptEx', 'LLPLLLPP', 'B', 'mswsock')
    API.new('bind', 'LPI', 'I', 'ws2_32')
    API.new('closesocket', 'L', 'I', 'ws2_32')
    API.new('connect', 'LPI', 'I', 'ws2_32')
    API.new('EnumProtocols', 'PPP', 'I', 'mswsock')
    API.new('GetAcceptExSockaddrs', 'PLLLPPPP', 'V', 'mswsock')
    API.new('GetAddressByName', 'LPPPLPPPPP', 'I', 'mswsock')
    API.new('gethostbyaddr', 'SII', 'P', 'ws2_32')
    API.new('gethostbyname', 'S', 'P', 'ws2_32')
    API.new('gethostname', 'PI', 'I', 'ws2_32')
    API.new('GetNameByType', 'PPL', 'I', 'mswsock')
    API.new('getpeername', 'LPP', 'I', 'ws2_32')
    API.new('getprotobyname', 'S', 'P', 'ws2_32')
    API.new('getprotobynumber', 'I', 'P', 'ws2_32')
    API.new('getservbyport', 'IS', 'P', 'ws2_32')
    API.new('GetService', 'LPSLPPP', 'I', 'mswsock')
    API.new('getsockname', 'LPP', 'I', 'ws2_32')
    API.new('getsockopt', 'LIIPP', 'I', 'ws2_32')
    API.new('GetTypeByName', 'LIIPP', 'I', 'mswsock')
    API.new('htonl', 'L', 'L', 'ws2_32')
    API.new('htons', 'S', 'S', 'ws2_32')
    API.new('inet_addr', 'S', 'L', 'ws2_32')
    API.new('inet_ntoa', 'P', 'S', 'ws2_32')
    API.new('ioctlsocket', 'LLP', 'I', 'ws2_32')
    API.new('listen', 'LI', 'I', 'ws2_32')
    API.new('ntohl', 'L', 'L', 'ws2_32')
    API.new('ntohs', 'S', 'S', 'ws2_32')
    API.new('recv', 'LPII', 'I', 'ws2_32')
    API.new('recvfrom', 'LPIIPP', 'I', 'ws2_32')
    API.new('send', 'LSII', 'I', 'ws2_32')
    API.new('sendto', 'LSIIPI', 'I', 'ws2_32')
    API.new('SetService', 'LLLPPP', 'I', 'mswsock')
    API.new('setsockopt', 'LIISI', 'I', 'ws2_32')
    API.new('shutdown', 'LI', 'I', 'ws2_32')
    API.new('socket', 'III', 'L', 'ws2_32')
    API.new('TransmitFile', 'LLLLPPL', 'B', 'mswsock')

    begin
      API.new('freeaddrinfo', 'P', 'V', 'ws2_32')
      API.new('FreeAddrInfoEx', 'P', 'V', 'ws2_32')
      API.new('FreeAddrInfoW', 'P', 'V', 'ws2_32')
      API.new('getaddrinfo', 'PPPP', 'I', 'ws2_32')
      API.new('GetAddrInfoEx', 'PPLPPPPPPP', 'I', 'ws2_32')
      API.new('GetAddrInfoW', 'PPPP', 'I', 'ws2_32')
      API.new('getnameinfo', 'PLPLPLI', 'I', 'ws2_32')
      API.new('GetNameInfoW', 'PLPLPLI', 'I', 'ws2_32')
      API.new('InetNtop', 'IPPL', 'P', 'ws2_32')
      API.new('inet_pton', 'IPP', 'I', 'ws2_32')
      API.new('SetAddrInfoEx', 'SSPLPLLPPPPP', 'I', 'ws2_32')
    rescue Win32::API::LoadLibraryError
      # XP or later
    end
  end
end
