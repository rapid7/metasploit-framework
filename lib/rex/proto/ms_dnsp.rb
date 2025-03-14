# -*- coding: binary -*-
# frozen_string_literal: true

require 'bindata'

module Rex::Proto
  module MsDnsp
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/39b03b89-2264-4063-8198-d62f62a6441a
    class DnsRecordType
      DNS_TYPE_ZERO = 0x0000
      DNS_TYPE_A = 0x0001
      DNS_TYPE_NS = 0x0002
      DNS_TYPE_MD = 0x0003
      DNS_TYPE_MF = 0x0004
      DNS_TYPE_CNAME = 0x0005
      DNS_TYPE_SOA = 0x0006
      DNS_TYPE_MB = 0x0007
      DNS_TYPE_MG = 0x0008
      DNS_TYPE_MR = 0x0009
      DNS_TYPE_NULL = 0x000A
      DNS_TYPE_WKS = 0x000B
      DNS_TYPE_PTR = 0x000C
      DNS_TYPE_HINFO = 0x000D
      DNS_TYPE_MINFO = 0x000E
      DNS_TYPE_MX = 0x000F
      DNS_TYPE_TXT = 0x0010
      DNS_TYPE_RP = 0x0011
      DNS_TYPE_AFSDB = 0x0012
      DNS_TYPE_X25 = 0x0013
      DNS_TYPE_ISDN = 0x0014
      DNS_TYPE_RT = 0x0015
      DNS_TYPE_SIG = 0x0018
      DNS_TYPE_KEY = 0x0019
      DNS_TYPE_AAAA = 0x001C
      DNS_TYPE_LOC = 0x001D
      DNS_TYPE_NXT = 0x001E
      DNS_TYPE_SRV = 0x0021
      DNS_TYPE_ATMA = 0x0022
      DNS_TYPE_NAPTR = 0x0023
      DNS_TYPE_DNAME = 0x0027
      DNS_TYPE_DS = 0x002B
      DNS_TYPE_RRSIG = 0x002E
      DNS_TYPE_NSEC = 0x002F
      DNS_TYPE_DNSKEY = 0x0030
      DNS_TYPE_DHCID = 0x0031
      DNS_TYPE_NSEC3 = 0x0032
      DNS_TYPE_NSEC3PARAM = 0x0033
      DNS_TYPE_TLSA = 0x0034
      DNS_TYPE_ALL = 0x00FF
      DNS_TYPE_WINS = 0xFF01
      DNS_TYPE_WINSR = 0xFF02
    end

    class MsDnspAddr4 < BinData::Primitive
      string :data, length: 4

      def get
        Rex::Socket.addr_ntoa(self.data)
      end

      def set(v)
        raise TypeError, 'must be an IPv4 address' unless Rex::Socket.is_ipv4?(v)

        self.data = Rex::Socket.addr_aton(v)
      end
    end

    class MsDnspAddr6 < BinData::Primitive
      string :data, length: 16

      def get
        Rex::Socket.addr_ntoa(self.data)
      end

      def set(v)
        raise TypeError, 'must be an IPv6 address' unless Rex::Socket.is_ipv6?(v)

        self.data = Rex::Socket.addr_aton(v)
      end
    end

    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8
    class MsDnspDnsRecord < BinData::Record
      endian :little

      uint16   :data_length, initial_value: -> { data.length }
      uint16   :record_type
      uint8    :version
      uint8    :rank
      uint16   :flags
      uint32   :serial
      uint32be :ttl_seconds
      uint32   :reserved
      uint32   :timestamp
      choice   :data, selection: :record_type do
        ms_dnsp_addr4 DnsRecordType::DNS_TYPE_A
        ms_dnsp_addr6 DnsRecordType::DNS_TYPE_AAAA
        string :default, read_length: :data_length
      end
    end
  end
end
