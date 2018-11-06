# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/ip/header'
require 'packetfu/protos/ip/mixin'

require 'packetfu/protos/icmp/header'
require 'packetfu/protos/icmp/mixin'

module PacketFu
  # ICMPPacket is used to construct ICMP Packets. They contain an EthHeader, an IPHeader, and a ICMPHeader.
  #
  # == Example
  #
  #  icmp_pkt.new
  #  icmp_pkt.icmp_type = 8
  #  icmp_pkt.icmp_code = 0
  #  icmp_pkt.payload = "ABC, easy as 123. As simple as do-re-mi. ABC, 123, baby, you and me!"
  #
  #  icmp_pkt.ip_saddr="1.2.3.4"
  #  icmp_pkt.ip_daddr="5.6.7.8"
  #
  #  icmp_pkt.recalc	
  #  icmp_pkt.to_f('/tmp/icmp.pcap')
  #
  # == Parameters
  #
  #  :eth
  #   A pre-generated EthHeader object.
  #  :ip
  #   A pre-generated IPHeader object.
  #  :flavor
  #   TODO: Sets the "flavor" of the ICMP packet. Pings, in particular, often betray their true
  #   OS.
  #  :config
  #   A hash of return address details, often the output of Utils.whoami?
  class ICMPPacket < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPHeaderMixin
    include ::PacketFu::ICMPHeaderMixin

    attr_accessor :eth_header, :ip_header, :icmp_header

    def self.can_parse?(str)
      return false unless str.size >= 38
      return false unless EthPacket.can_parse? str
      return false unless IPPacket.can_parse? str
      return false unless str[23,1] == "\x01"
      return true
    end

    def read(str=nil, args={})
      raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
      @eth_header.read(str)
      super(args)
      self
    end

    def initialize(args={})
      @eth_header = EthHeader.new(args).read(args[:eth])
      @ip_header = IPHeader.new(args).read(args[:ip])
      @ip_header.ip_proto = 1
      @icmp_header = ICMPHeader.new(args).read(args[:icmp])

      @ip_header.body = @icmp_header
      @eth_header.body = @ip_header

      @headers = [@eth_header, @ip_header, @icmp_header]
      super
    end

    # Peek provides summary data on packet contents.
    def peek_format
      peek_data = ["IC "] # I is taken by IP
      peek_data << "%-5d" % self.to_s.size
      type = case self.icmp_type.to_i
             when 8
               "ping"
             when 0
               "pong"
             else
               "%02x-%02x" % [self.icmp_type, self.icmp_code]
             end
      peek_data << "%-21s" % "#{self.ip_saddr}:#{type}"
      peek_data << "->"
      peek_data << "%21s" % "#{self.ip_daddr}"
      peek_data << "%23s" % "I:"
      peek_data << "%04x" % self.ip_id
      peek_data.join
    end
  end
end
