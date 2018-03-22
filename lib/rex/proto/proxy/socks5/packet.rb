# -*- coding: binary -*-

require 'bindata'
require 'rex/socket'

module Rex
module Proto
module Proxy

module Socks5
  SOCKS_VERSION = 5

  class AuthRequestPacket < BinData::Record
    endian :big

    uint8  :version, :initial_value => SOCKS_VERSION
    uint8  :supported_methods_length
    array  :supported_methods, :type => :uint8, :initial_length => :supported_methods_length
  end

  class AuthResponsePacket < BinData::Record
    endian :big

    uint8  :version, :initial_value => SOCKS_VERSION
    uint8  :chosen_method
  end

  module AddressMixin
    ADDRESS_TYPE_IPV4               = 1
    ADDRESS_TYPE_DOMAINNAME         = 3
    ADDRESS_TYPE_IPV6               = 4

    def address
      addr = address_array.to_ary.pack('C*')
      if address_type == ADDRESS_TYPE_IPV4 || address_type == ADDRESS_TYPE_IPV6
        addr = Rex::Socket.addr_ntoa(addr)
      end
      addr
    end

    def address=(value)
      if Rex::Socket.is_ipv4?(value)
        address_type.assign(ADDRESS_TYPE_IPV4)
        domainname_length.assign(0)
      elsif Rex::Socket.is_ipv6?(value)
        address_type.assign(ADDRESS_TYPE_IPV6)
        domainname_length.assign(0)
      else
        address_type.assign(ADDRESS_TYPE_DOMAINNAME)
        domainname_length.assign(value.length)
      end
      address_array.assign(Rex::Socket.addr_aton(value).unpack('C*'))
    end

    def address_length
      case address_type
        when ADDRESS_TYPE_IPV4
          4
        when ADDRESS_TYPE_DOMAINNAME
          domainname_length
        when ADDRESS_TYPE_IPV6
          16
        else
          0
      end
    end
  end

  class RequestPacket < BinData::Record
    include AddressMixin
    endian :big
    hide   :reserved, :domainname_length

    uint8  :version, :initial_value => SOCKS_VERSION
    uint8  :command
    uint8  :reserved
    uint8  :address_type
    uint8  :domainname_length, :onlyif => lambda { address_type == ADDRESS_TYPE_DOMAINNAME }
    array  :address_array, :type => :uint8, :initial_length => lambda { address_length }
    uint16 :port
  end

  class ResponsePacket < RequestPacket
  end
end
end
end
end
