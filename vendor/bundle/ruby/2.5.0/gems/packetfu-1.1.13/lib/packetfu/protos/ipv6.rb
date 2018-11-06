# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/ipv6/header'
require 'packetfu/protos/ipv6/mixin'

module PacketFu
  # IPv6Packet is used to construct IPv6 Packets. They contain an EthHeader and an IPv6Header, and in
  # the distant, unknowable future, will take interesting IPv6ish payloads.
  #
  # This mostly complete, but not very useful. It's intended primarily as an example protocol.
  #
  # == Parameters
  #
  #   :eth
  #     A pre-generated EthHeader object.
  #   :ip
  #     A pre-generated IPHeader object.
  #   :flavor
  #     TODO: Sets the "flavor" of the IPv6 packet. No idea what this will look like, haven't done much IPv6 fingerprinting.
  #   :config
  #     A hash of return address details, often the output of Utils.whoami?
  class IPv6Packet < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPv6HeaderMixin

    attr_accessor :eth_header, :ipv6_header

    def self.can_parse?(str)
      return false unless EthPacket.can_parse? str
      return false unless str.size >= 54
      return false unless str[12,2] == "\x86\xdd"
      true
    end

    def read(str=nil,args={})
      raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
      @eth_header.read(str)
      super(args)
      self
    end

    def initialize(args={})
      @eth_header = (args[:eth] || EthHeader.new)
      @ipv6_header = (args[:ipv6]	|| IPv6Header.new)
      @eth_header.eth_proto = 0x86dd
      @eth_header.body=@ipv6_header
      @headers = [@eth_header, @ipv6_header]
      super
    end

    # Peek provides summary data on packet contents.
    def peek(args={})
      peek_data = ["6  "]
      peek_data << "%-5d" % self.to_s.size
      peek_data << "%-31s" % self.ipv6_saddr
      peek_data << "-> "
      peek_data << "%-31s" % self.ipv6_daddr
      peek_data << "  N:"
      peek_data << self.ipv6_next.to_s(16)
      peek_data.join
    end

  end
  
end
