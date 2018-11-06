# -*- coding: binary -*-
require 'packetfu/common'
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'
require 'packetfu/protos/arp/header'
require 'packetfu/protos/arp/mixin'

module PacketFu

  # ARPPacket is used to construct ARP packets. They contain an EthHeader and an ARPHeader.
  # == Example
  #
  #  require 'packetfu'
  #  arp_pkt = PacketFu::ARPPacket.new(:flavor => "Windows")
  #  arp_pkt.arp_saddr_mac="00:1c:23:44:55:66"  # Your hardware address
  #  arp_pkt.arp_saddr_ip="10.10.10.17"  # Your IP address
  #  arp_pkt.arp_daddr_ip="10.10.10.1"  # Target IP address
  #  arp_pkt.arp_opcode=1  # Request
  #
  #  arp_pkt.to_w('eth0')	# Inject on the wire. (requires root)
  #  arp_pkt.to_f('/tmp/arp.pcap') # Write to a file.
  #
  # == Parameters
  #
  #  :flavor
  #   Sets the "flavor" of the ARP packet. Choices are currently:
  #     :windows, :linux, :hp_deskjet
  #  :eth
  #   A pre-generated EthHeader object. If not specified, a new one will be created.
  #  :arp
  #   A pre-generated ARPHeader object. If not specificed, a new one will be created.
  #  :config
  #   A hash of return address details, often the output of Utils.whoami?
  class ARPPacket < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::ARPHeaderMixin

    attr_accessor :eth_header, :arp_header

    def self.can_parse?(str)
      return false unless EthPacket.can_parse? str
      return false unless str.size >= 28
      return false unless str[12,2] == "\x08\x06"
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
      @arp_header = ARPHeader.new(args).read(args[:arp])
      @eth_header.eth_proto = "\x08\x06"
      @eth_header.body=@arp_header

      # Please send more flavors to todb+packetfu@planb-security.net.
      # Most of these initial fingerprints come from one (1) sample.
      case (args[:flavor].nil?) ? :nil : args[:flavor].to_s.downcase.intern
      when :windows; @arp_header.body = "\x00" * 64				# 64 bytes of padding
      when :linux; @arp_header.body = "\x00" * 4 +				# 32 bytes of padding
        "\x00\x07\x5c\x14" + "\x00" * 4 +
        "\x00\x0f\x83\x34" + "\x00\x0f\x83\x74" +
        "\x01\x11\x83\x78" + "\x00\x00\x00\x0c" +
        "\x00\x00\x00\x00"
      when :hp_deskjet; 																	# Pads up to 60 bytes.
        @arp_header.body = "\xe0\x90\x0d\x6c" +
        "\xff\xff\xee\xee" + "\x00" * 4 +
        "\xe0\x8f\xfa\x18\x00\x20"
      else; @arp_header.body = "\x00" * 18								# Pads up to 60 bytes.
      end

      @headers = [@eth_header, @arp_header]
      super
    end

    # Generates summary data for ARP packets.
    def peek_format
      peek_data = ["A  "]
      peek_data << "%-5d" % self.to_s.size
      peek_data << arp_saddr_mac
      peek_data << "(#{arp_saddr_ip})"
      peek_data << "->"
      peek_data << case arp_daddr_mac
                    when "00:00:00:00:00:00"; "Bcast00"
                    when "ff:ff:ff:ff:ff:ff"; "BcastFF"
                    else; arp_daddr_mac
                    end
      peek_data << "(#{arp_daddr_ip})"
      peek_data << ":"
      peek_data << case arp_opcode
                    when 1; "Requ"
                    when 2; "Repl"
                    when 3; "RReq"
                    when 4; "RRpl"
                    when 5; "IReq"
                    when 6; "IRpl"
                    else; "0x%02x" % arp_opcode
                    end
      peek_data.join
    end

    # While there are lengths in ARPPackets, there's not
    # much to do with them.
    def recalc(args={})
      @headers[0].inspect
    end

  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
