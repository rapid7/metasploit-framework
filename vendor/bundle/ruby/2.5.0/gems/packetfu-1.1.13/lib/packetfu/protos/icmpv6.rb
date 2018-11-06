# coding: binary
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/ipv6/header'
require 'packetfu/protos/ipv6/mixin'

require 'packetfu/protos/icmpv6/header'
require 'packetfu/protos/icmpv6/mixin'

module PacketFu

  # ICMPv6Packet is used to construct ICMPv6 Packets. They contain an EthHeader,
  # an IPv6Header, and a ICMPv6Header.
  #
  # == Example
  #
  #  icmpv6_pkt.new
  #  icmpv6_pkt.icmpv6_type = 8
  #  icmpv6_pkt.icmpv6_code = 0
  #  icmpv6_pkt.payload = "ABC, easy as 123. As simple as do-re-mi. ABC, 123, baby, you and me!"
  #
  #  icmpv6_pkt.ipv6_saddr="2000::1234"
  #  icmpv6_pkt.ipv6_daddr="2000::5678"
  #
  #  icmpv6_pkt.recalc	
  #  icmpv6_pkt.to_f('/tmp/icmpv6.pcap')
  #
  # == Parameters
  #
  #  :eth
  #     A pre-generated EthHeader object.
  #  :ipv6
  #     A pre-generated IPv6Header object.
  #  :icmpv6
  #     A pre-generated ICMPv6Header object.
  class ICMPv6Packet < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPv6HeaderMixin
    include ::PacketFu::ICMPv6HeaderMixin

    attr_accessor :eth_header, :ipv6_header, :icmpv6_header

    def self.can_parse?(str)
      return false unless str.size >= 58
      return false unless EthPacket.can_parse? str
      return false unless IPv6Packet.can_parse? str
      return false unless str[20,1] == [PacketFu::ICMPv6Header::PROTOCOL_NUMBER].pack('C')
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
      @ipv6_header = IPv6Header.new(args).read(args[:ipv6])
      @ipv6_header.ipv6_next = PacketFu::ICMPv6Header::PROTOCOL_NUMBER
      @icmpv6_header = ICMPv6Header.new(args).read(args[:icmpv6])

      @ipv6_header.body = @icmpv6_header
      @eth_header.body = @ipv6_header

      @headers = [@eth_header, @ipv6_header, @icmpv6_header]
      super
      icmpv6_calc_sum
    end

    # Calculates the checksum for the object.
    def icmpv6_calc_sum
      checksum = 0

      # Compute sum on pseudo-header
      [ipv6_src, ipv6_dst].each do |iaddr|
        8.times { |i| checksum += (iaddr >> (i*16)) & 0xffff }
      end
      checksum += PacketFu::ICMPv6Header::PROTOCOL_NUMBER
      checksum += ipv6_len
      # Then compute it on ICMPv6 header + payload
      checksum += (icmpv6_type.to_i << 8) + icmpv6_code.to_i
      chk_body = (payload.to_s.size % 2 == 0 ? payload.to_s : payload.to_s + "\x00")
      if 1.respond_to? :ord
        chk_body.split("").each_slice(2).map { |x| (x[0].ord << 8) + x[1].ord }.
          each { |y| checksum += y }
      else
        chk_body.split("").each_slice(2).map { |x| (x[0] << 8) + x[1] }.
          each { |y| checksum += y }
      end
      checksum = checksum % 0xffff
      checksum = 0xffff - checksum
      checksum == 0 ? 0xffff : checksum
    end

    # Recalculates the calculatable fields for ICMPv6.
    def icmpv6_recalc(arg=:all)
      arg = arg.intern if arg.respond_to? :intern
      case arg
      when :icmpv6_sum
        self.icmpv6_sum = icmpv6_calc_sum
      when :all
        self.icmpv6_sum = icmpv6_calc_sum
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # Peek provides summary data on packet contents.
    def peek_format
      peek_data = ["6C "]
      peek_data << "%-5d" % self.to_s.size
      type = case self.icmpv6_type.to_i
             when 128
               "ping"
             when 129
               "pong"
             else
               "%02x-%02x" % [self.icmpv6_type, self.icmpv6_code]
             end
      peek_data << "%-21s" % "#{self.ipv6_saddr}:#{type}"
      peek_data << "->"
      peek_data << "%21s" % "#{self.ipv6_daddr}"
      peek_data.join
    end

  end

end
