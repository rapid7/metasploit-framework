# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

module PacketFu
  # EthPacket is used to construct Ethernet packets. They contain an
  # Ethernet header, and that's about it.
  #
  # == Example
  #
  #   require 'packetfu'
  #   eth_pkt = PacketFu::EthPacket.new
  #   eth_pkt.eth_saddr="00:1c:23:44:55:66"
  #   eth_pkt.eth_daddr="00:1c:24:aa:bb:cc"
  #
  #   eth_pkt.to_w('eth0') # Inject on the wire. (require root)
  #
  class	EthPacket < Packet
    include ::PacketFu::EthHeaderMixin

    attr_accessor :eth_header

    def self.can_parse?(str)
      # XXX Temporary fix. Need to extend the EthHeader class to handle more.
      valid_eth_types = [0x0800, 0x0806, 0x86dd, 0x88cc]
      return false unless str.size >= 14
      type = str[12,2].unpack("n").first rescue nil
      return false unless valid_eth_types.include? type
      true
    end

    def read(str=nil,args={})
      raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
      @eth_header.read(str)
      super(args)
      return self
    end

    # Does nothing, really, since there's no length or
    # checksum to calculate for a straight Ethernet packet.
    def recalc(args={})
      @headers[0].inspect
    end

    def initialize(args={})
      @eth_header = EthHeader.new(args).read(args[:eth])
      @headers = [@eth_header]
      super
    end

  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
