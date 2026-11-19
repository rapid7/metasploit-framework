require 'spec_helper'
require 'msf/core/packet_fu_compat'

RSpec.describe Msf::PacketFuCompat do
  it 'converts packed Ethernet protocol bytes to the field value' do
    header = PacketFu::EthHeader.new

    header.eth_proto = "\x86\xdd".b

    expect(header.eth_proto).to eq(0x86dd)
  end

  it 'preserves assigned ARP fields when serializing and parsing a packet' do
    packet = PacketFu::ARPPacket.new
    packet.arp_opcode = 2
    packet.arp_saddr_ip = '192.0.2.1'
    packet.arp_daddr_ip = '192.0.2.2'
    packet.recalc

    parsed = PacketFu::Packet.parse(packet.to_s)

    expect([parsed.eth_proto, parsed.arp_opcode, parsed.arp_saddr_ip, parsed.arp_daddr_ip]).to eq([0x0806, 2, '192.0.2.1', '192.0.2.2'])
  end

  it 'assigns the lowest UDP port without changing the destination port' do
    packet = PacketFu::UDPPacket.new
    packet.udp_dst = 53

    packet.udp_src = 0

    expect([packet.ip_proto, packet.udp_src, packet.udp_dst]).to eq([17, 0, 53])
  end

  it 'assigns the highest UDP port without changing the source port' do
    packet = PacketFu::UDPPacket.new
    packet.udp_src = 53

    packet.udp_dst = 65_535

    expect([packet.ip_proto, packet.udp_src, packet.udp_dst]).to eq([17, 53, 65_535])
  end

  it 'preserves a TCP sequence number at the unsigned 32-bit boundary' do
    packet = PacketFu::TCPPacket.new

    packet.tcp_seq = 0xffff_ffff

    expect([packet.ip_proto, packet.tcp_seq]).to eq([6, 0xffff_ffff])
  end

  it 'assigns ICMP fields independently' do
    packet = PacketFu::ICMPPacket.new
    packet.icmp_type = 3
    packet.icmp_code = 1

    expect([packet.ip_proto, packet.icmp_type, packet.icmp_code]).to eq([1, 3, 1])
  end

  it 'assigns IPv6 fields independently' do
    packet = PacketFu::IPv6Packet.new
    packet.ipv6_next = 17
    packet.ipv6_hop = 255

    expect([packet.eth_proto, packet.ipv6_next, packet.ipv6_hop]).to eq([0x86dd, 17, 255])
  end

  it 'preserves binary payloads through the StructFu body setter' do
    packet = PacketFu::UDPPacket.new
    payload = "\x00\xff\x80payload".b

    packet.payload = payload
    packet.recalc

    expect(PacketFu::Packet.parse(packet.to_s).payload).to eq(payload)
  end

  it 'supports inherited packet field setters' do
    header = Class.new(PacketFu::EthHeader).new

    header.eth_proto = 0x0806

    expect(header.eth_proto).to eq(0x0806)
  end

  it 'supports singleton packet field setters' do
    header = PacketFu::EthHeader.new
    def header.eth_proto=(value)
      typecast(value)
    end

    header.eth_proto = 0x0806

    expect(header.eth_proto).to eq(0x0806)
  end
end
