# -*- coding: binary -*-

module Rex
  module Proto
    # Constants for DHCPv6 (RFC 8415), plus the DNS configuration options from
    # RFC 3646. Only the subset needed to run a rogue stateful/stateless DHCPv6
    # server (to become a client's DNS server) is defined here.
    module DHCPv6::Constants
      # DHCPv6 message types (RFC 8415 section 7.3)
      module MessageType
        SOLICIT = 1
        ADVERTISE = 2
        REQUEST = 3
        CONFIRM = 4
        RENEW = 5
        REBIND = 6
        REPLY = 7
        RELEASE = 8
        DECLINE = 9
        RECONFIGURE = 10
        INFORMATION_REQUEST = 11
        RELAY_FORW = 12
        RELAY_REPL = 13
      end

      # DHCPv6 option codes (RFC 8415 section 21, RFC 3646 for DNS options)
      module OptionCode
        CLIENTID = 1
        SERVERID = 2
        IA_NA = 3
        IA_TA = 4
        IAADDR = 5
        ORO = 6 # Option Request Option
        PREFERENCE = 7
        ELAPSED_TIME = 8
        STATUS_CODE = 13
        RAPID_COMMIT = 14
        DNS_SERVERS = 23 # RFC 3646: DNS Recursive Name Server option
        DOMAIN_LIST = 24 # RFC 3646: Domain Search List option
      end

      # DUID types (RFC 8415 section 11)
      module DuidType
        LLT = 1 # Link-layer address plus time
        EN = 2 # Vendor-assigned unique ID based on Enterprise Number
        LL = 3 # Link-layer address
      end

      # Status codes (RFC 8415 section 21.13)
      module StatusCode
        SUCCESS = 0
        UNSPEC_FAIL = 1
        NO_ADDRS_AVAIL = 2
        NO_BINDING = 3
        NOT_ON_LINK = 4
        USE_MULTICAST = 5
      end

      # Hardware type for DUID-LL/LLT (IANA; 1 = Ethernet)
      HARDWARE_TYPE_ETHERNET = 1

      # The well-known multicast group all DHCPv6 servers and relay agents listen
      # on, and the server/client UDP ports (RFC 8415 section 7.2).
      ALL_DHCP_RELAY_AGENTS_AND_SERVERS = 'ff02::1:2'
      SERVER_PORT = 547
      CLIENT_PORT = 546
    end
  end
end
