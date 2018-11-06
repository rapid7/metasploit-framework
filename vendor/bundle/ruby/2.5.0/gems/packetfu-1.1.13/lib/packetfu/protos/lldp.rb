# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/lldp/header'
require 'packetfu/protos/lldp/mixin'

module PacketFu

  class LLDPPacket < Packet
    MAGIC = Regexp.new("^\x01\x80\xc2\x00\x00[\x0e\x03\x00]", nil, "n")
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::LLDPHeaderMixin

    attr_accessor :eth_header, :lldp_header

    def self.can_parse?(str)
      return false unless EthPacket.can_parse? str
      return false unless str.size >= 6
      return false unless str[12,2] == "\x88\xcc"
      return false unless str =~ MAGIC
      true
    end

    def read(str=nil,args={})
      raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
      @eth_header.read(str)
      super(args)
      self
    end

    def initialize(args={})
      @eth_header = EthHeader.new(args).read(args[:eth])
      @lldp_header = LLDPHeader.new(args).read(args[:lldp])
      @eth_header.eth_proto = "\x88\xCC"
      @eth_header.body=@lldp_header

      @headers = [@eth_header, @lldp_header]
      super
    end

    # Generates summary data for LLDP packets.
    def peek_format
      peek_data = ["A  "]
      peek_data << "%-5d" % self.to_s.size
      peek_data << lldp_saddr_mac
      peek_data << "(#{lldp_saddr_mac})"
      peek_data << "->"
      peek_data << "01:80:c2:00:00:0e"
      peek_data.join
    end

    # While there are lengths in LLDPPackets, there's not
    # much to do with them.
    def recalc(args={})
      @headers[0].inspect
    end
  end
end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
