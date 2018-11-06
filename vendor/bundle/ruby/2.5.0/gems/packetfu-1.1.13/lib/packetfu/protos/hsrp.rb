# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/ip/header'
require 'packetfu/protos/ip/mixin'

require 'packetfu/protos/udp/header'
require 'packetfu/protos/udp/mixin'

require 'packetfu/protos/hsrp/header'
require 'packetfu/protos/hsrp/mixin'

module PacketFu
  # HSRPPacket is used to construct HSRP Packets. They contain an EthHeader, an IPHeader, and a UDPHeader.
  #
  # == Example
  #
  #  hsrp_pkt.new
  #  hsrp_pkt.hsrp_opcode = 0
  #  hsrp_pkt.hsrp_state = 16
  #  hsrp_pkt.hsrp_priority = 254
  #  hsrp_pkt.hsrp_group = 1
  #  hsrp_pkt.hsrp_vip = 10.100.100.254
  #  hsrp_pkt.recalc
  #  hsrp_pkt.to_f('/tmp/hsrp.pcap')
  #
  # == Parameters
  #
  #  :eth
  #   A pre-generated EthHeader object.
  #  :ip
  #   A pre-generated IPHeader object.
  #  :udp
  #   A pre-generated UDPHeader object.
  #  :flavor
  #   TODO: HSRP packets don't tend have any flavor.
  #  :config
  #   A hash of return address details, often the output of Utils.whoami?
  class HSRPPacket < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPHeaderMixin
    include ::PacketFu::UDPHeaderMixin
    include ::PacketFu::HSRPHeaderMixin

    attr_accessor :eth_header, :ip_header, :udp_header, :hsrp_header

    def self.can_parse?(str)
      return false unless str.size >= 54
      return false unless EthPacket.can_parse? str
      return false unless IPPacket.can_parse? str
      return false unless UDPPacket.can_parse? str
      temp_packet = UDPPacket.new
      temp_packet.read(str)
      if temp_packet.ip_ttl == 1 and [temp_packet.udp_sport,temp_packet.udp_dport] == [1985,1985] 
        return true
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

    def initialize(args={})
      @eth_header = EthHeader.new(args).read(args[:eth])
      @ip_header = IPHeader.new(args).read(args[:ip])
      @ip_header.ip_proto = 0x11
      @udp_header = UDPHeader.new(args).read(args[:udp])
      @hsrp_header = HSRPHeader.new(args).read(args[:hsrp])
      @udp_header.body = @hsrp_header
      @ip_header.body = @udp_header
      @eth_header.body = @ip_header
      @headers = [@eth_header, @ip_header, @udp_header, @hsrp_header]
      super
    end

    # Peek provides summary data on packet contents.
    def peek_format
      peek_data = ["UH "]
      peek_data << "%-5d" % self.to_s.size
      peek_data << "%-16s" % self.hsrp_addr
      peek_data << "%-4d" % self.hsrp_group
      peek_data << "%-35s" % self.hsrp_password_readable
      peek_data << "%-15s" % self.ip_saddr
      peek_data.join
    end

  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
