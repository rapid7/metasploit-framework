# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'
require 'packetfu/protos/ip/header'
require 'packetfu/protos/ip/mixin'

module PacketFu

  # IPPacket is used to construct IP packets. They contain an EthHeader, an IPHeader, and usually
  # a transport-layer protocol such as UDPHeader, TCPHeader, or ICMPHeader.
  #
  # == Example
  #
  #   require 'packetfu'
  #   ip_pkt = PacketFu::IPPacket.new
  #   ip_pkt.ip_saddr="10.20.30.40"
  #   ip_pkt.ip_daddr="192.168.1.1"
  #   ip_pkt.ip_proto=1
  #   ip_pkt.ip_ttl=64
  #   ip_pkt.ip_payload="\x00\x00\x12\x34\x00\x01\x00\x01"+
  #     "Lovingly hand-crafted echo responses delivered directly to your door."
  #   ip_pkt.recalc
  #   ip_pkt.to_f('/tmp/ip.pcap')
  #
  # == Parameters
  #
  #   :eth
  #     A pre-generated EthHeader object.
  #   :ip
  #     A pre-generated IPHeader object.
  #   :flavor
  #     TODO: Sets the "flavor" of the IP packet. This might include known sets of IP options, and
  #     certainly known starting TTLs.
  #   :config
  #     A hash of return address details, often the output of Utils.whoami?
  class IPPacket < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPHeaderMixin

    attr_accessor :eth_header, :ip_header

    def self.can_parse?(str)
      return false unless str.size >= 34
      return false unless EthPacket.can_parse? str
      if str[12,2] == "\x08\x00"
        if 1.respond_to? :ord
          ipv = str[14,1][0].ord >> 4
        else
          ipv = str[14,1][0] >> 4
        end
        return true if ipv == 4
      else
        return false
      end
    end

    def read(str=nil, args={})
      raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
      @eth_header.read(str)
      super(args)
      self
    end

    # Creates a new IPPacket object.
    def initialize(args={})
      @eth_header = EthHeader.new(args).read(args[:eth])
      @ip_header = IPHeader.new(args).read(args[:ip])
      @eth_header.body=@ip_header

      @headers = [@eth_header, @ip_header]
      super
    end

    # Peek provides summary data on packet contents.
    def peek_format
      peek_data = ["I  "]
      peek_data << "%-5d" % to_s.size
      peek_data << "%-21s" % "#{ip_saddr}"
      peek_data << "->"
      peek_data << "%21s" % "#{ip_daddr}"
      peek_data << "%23s" % "I:"
      peek_data << "%04x" % ip_id.to_i
      peek_data.join
    end

  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
