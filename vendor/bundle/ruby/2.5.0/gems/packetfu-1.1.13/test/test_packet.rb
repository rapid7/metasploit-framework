#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'test/unit'
$:.unshift File.expand_path(File.join(File.dirname(__FILE__), "..", "lib"))
require 'packetfu'

class NewPacketTest < Test::Unit::TestCase
  include PacketFu
  
  def test_method_missing_and_respond_to
    p = TCPPacket.new
    assert p.respond_to?(:ip_len)
    assert p.ip_len = 20
    assert !(p.respond_to? :ip_bogus_header)
    assert_raise NoMethodError do
      p.bogus_header = 20
    end
  end

  def test_more_method_missing_magic
    p = UDPPacket.new
    assert_kind_of(UDPPacket,p)
    assert p.is_udp?
    assert p.is_ip?
    assert p.is_eth?
    assert_equal(p.ip_hl,5)
    assert p.layer
    assert_raise NoMethodError do 
      p.is_blue? 
    end
    assert_raise NoMethodError do
       p.tcp_blue
    end
    assert_raise NoMethodError do 
      p.udp_blue 
    end
    assert_raise NoMethodError do
      p.blue
    end
  end
end

class PacketStrippingTest < Test::Unit::TestCase

  include PacketFu

  def test_arp_strip
    pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
    p = Packet.parse(pcaps[5], :fix => true) # Really ARP request.
    assert_kind_of(Packet,p)
    assert_kind_of(ARPPacket,p)
  end

end

class PacketParsersTest < Test::Unit::TestCase
  include PacketFu

  def test_parse_eth_packet
    assert_equal(EthPacket.layer, 1)
    assert_equal(EthPacket.layer_symbol, :link)
    pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
    p = Packet.parse(pcaps[5]) # Really ARP.
    assert_kind_of(Packet,p)
    assert_kind_of(EthHeader, p.headers[0])
    assert p.is_eth?
    assert_equal(pcaps[5],p.to_s)
  end

  def test_parse_arp_request
    assert_equal(ARPPacket.layer, 2)
    pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
    p = Packet.parse(pcaps[5]) # Really ARP request.
    assert p.is_eth?
    assert_kind_of(EthPacket,p)
    assert_kind_of(ARPPacket,p)
    assert p.is_arp?
    assert_equal(p.to_s, pcaps[5])
    assert_equal(1, p.arp_opcode.to_i)
    assert_equal("\x00\x01", p.headers.last[:arp_opcode].to_s)
  end

  def test_parse_arp_reply
    assert_equal(ARPPacket.layer, 2)
    pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
    p = Packet.parse(pcaps[6]) # Really ARP reply.
    assert_equal(p.to_s, pcaps[6])
    assert_equal(2, p.arp_opcode.to_i)
    assert_equal("\x00\x02", p.headers.last[:arp_opcode].to_s)
  end

  def test_parse_ip_packet
    assert_equal(IPPacket.layer, 2)
    pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
    p = Packet.parse(pcaps[0]) # Really DNS request 
    assert_equal(p.to_s[0,20], pcaps[0][0,20])
    assert_equal(p.to_s, pcaps[0])
    assert_kind_of(EthPacket,p)
    assert_kind_of(IPPacket,p)
  end

  def test_parse_tcp_packet
    assert_equal(TCPPacket.layer, 3)
    pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
    p = Packet.parse(pcaps[7]) # Really FIN/ACK
    assert_equal(p.to_s, pcaps[7])
    assert_kind_of(EthPacket,p)
    assert_kind_of(IPPacket,p)
    assert_kind_of(TCPPacket,p)
  end

  def test_parse_udp_packet
    assert_equal(UDPPacket.layer, 3)
    pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
    p = Packet.parse(pcaps[0]) # Really DNS request
    assert_equal(p.to_s, pcaps[0])
    assert_kind_of(EthPacket,p)
    assert_kind_of(IPPacket,p)
    assert_kind_of(UDPPacket,p)
  end

  def test_parse_icmp_packet
    assert_equal(ICMPPacket.layer, 3)
    assert_equal(ICMPPacket.layer_symbol, :transport)
    pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
    p = Packet.parse(pcaps[3]) # Really ICMP reply
    assert_equal(p.to_s, pcaps[3])
    assert_kind_of(EthPacket,p)
    assert_kind_of(IPPacket,p)
    assert_kind_of(ICMPPacket,p)
  end

  def test_parse_invalid_packet
    assert_equal(InvalidPacket.layer, 0)
    assert_equal(InvalidPacket.layer_symbol, :invalid)
    p = Packet.parse("\xff\xfe\x00\x01")
    assert_equal(p.to_s, "\xff\xfe\x00\x01")
    assert_kind_of(InvalidPacket,p)
  end

  def test_parse_ipv6_packet
    assert_equal(IPv6Packet.layer, 2)
    assert_equal(IPv6Packet.layer_symbol, :internet)
    pcaps = PcapFile.new.file_to_array(:f => 'sample-ipv6.pcap')
    p = Packet.parse(pcaps[0]) # Really an IPv6 packet 
    assert_equal(p.to_s, pcaps[0])
    assert_kind_of(EthPacket,p)
    assert(!p.kind_of?(IPPacket), "Misidentified as an IP Packet!")
    assert_kind_of(IPv6Packet,p)
  end

  def test_parse_hsrp_packet
    assert_equal(HSRPPacket.layer, 4)
    assert_equal(HSRPPacket.layer_symbol, :application)
    pcaps = PcapFile.new.file_to_array(:f => 'sample_hsrp_pcapr.cap')
    p = Packet.parse(pcaps[0]) # Really an HSRP Hello packet 
    assert_equal(p.to_s, pcaps[0])
    assert_kind_of(EthPacket,p)
    assert_kind_of(IPPacket,p)
    assert_kind_of(UDPPacket,p)
    assert_kind_of(HSRPPacket,p)
  end

  def test_parse_hsrp_as_udp
    assert_equal(:application, HSRPPacket.layer_symbol)
    pcaps = PcapFile.new.file_to_array(:f => 'sample_hsrp_pcapr.cap')
    p = Packet.parse(pcaps[0], :parse_app => false) # Really an HSRP Hello packet 
    assert_kind_of(UDPPacket,p)
    assert(!p.kind_of?(HSRPPacket), "Misidentified HSRP packet when we didn't want it!" )
  end

end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
