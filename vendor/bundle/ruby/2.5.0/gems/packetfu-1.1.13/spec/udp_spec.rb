require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/udp'
require 'packetfu/pcap'

include PacketFu

class String
  def bin
    self.scan(/../).map {|x| x.to_i(16).chr}.join
  end
end

describe UDPPacket do

  context 'when read from a pcap file' do
    context '(UDP over IPv4)' do
      before(:all) do
        @udp4_packet = PcapFile.read_packets(File.join(File.dirname(__FILE__),
                                                       "ipv4_udp.pcap")).first
      end

      it 'should be recognized as a UDP packet' do
        expect(@udp4_packet.is_udp?).to be(true)
        expect(@udp4_packet.ipv6?).to be(false)
      end

      it 'should have the right port numbers' do
        expect(@udp4_packet.udp_src).to eq(41000)
        expect(@udp4_packet.udp_dst).to eq(42000)
      end

      it 'should have the right length' do
        expect(@udp4_packet.udp_len).to eq(24)
      end

      it 'should have the right checksum' do
        expect(@udp4_packet.udp_sum).to eq(0xbd81)
      end
    end

    context '(UDP over IPv6)' do
      before(:all) do
        @udp6_packet = PcapFile.read_packets(File.join(File.dirname(__FILE__),
                                                       "ipv6_udp.pcap")).first
      end

      it 'should be recognized as a UDP packet' do
        expect(@udp6_packet.is_udp?).to be(true)
        expect(@udp6_packet.ipv6?).to be(true)
      end

      it 'should have the right port numbers' do
        expect(@udp6_packet.udp_src).to eq(6809)
        expect(@udp6_packet.udp_dst).to eq(6810)
      end

      it 'should have the right length' do
        expect(@udp6_packet.udp_len).to eq(12)
      end

      it 'should have the right checksum' do
        expect(@udp6_packet.udp_sum).to eq(0xb9be)
      end
    end

    context 'UDP over IPv4 v2' do
      it "should have all the UDP attributes" do
        udp_packet = PcapFile.new.file_to_array(:f => 'test/sample.pcap')[0]
        udp_pkt = Packet.parse(udp_packet)
        expect(udp_pkt).to be_kind_of(UDPPacket)
        expect(udp_pkt.udp_sum.to_i).to eql(0x8bf8)
      end
    end

    context 'UDP over IPv4 alter' do
      it "should read and allow us to alert the payload" do
        udp_packet = PcapFile.new.file_to_array(:f => 'test/sample.pcap')[0]
        udp_pkt = Packet.parse(udp_packet)
        expect(udp_pkt).to be_kind_of(UDPPacket)

        udp_pkt.payload = udp_pkt.payload.gsub(/metasploit/,"MeatPistol")
        udp_pkt.recalc
        expect(udp_pkt.udp_sum).to eql(0x8341)
      end
    end
  end

  context "when initializing UDPHeader from scratch" do
    before(:each) { @udp_header = UDPHeader.new }
    it 'should have the right instance variables' do
      expect(@udp_header).to be_kind_of(UDPHeader)
      expect(@udp_header.to_s.size).to eql(8)
      expect(@udp_header.to_s).to eql("\x00\x00\x00\x00\x00\b\x00\x00")
      expect(@udp_header.udp_src).to eq(0)
      expect(@udp_header.udp_dst).to eq(0)
      expect(@udp_header.udp_len).to eq(8)
      expect(@udp_header.udp_sum).to eq(0)
    end

    it 'should allow setting of port numbers' do
      @udp_header.udp_src = 1024
      @udp_header.udp_dst = 1025
      expect(@udp_header.udp_src).to eq(1024)
      expect(@udp_header.udp_dst).to eq(1025)
    end
  end

  context "when initializing UDPPacket from scratch" do
    it "should create UDP on IPv4 packets by default" do
      udp = UDPPacket.new
      expect(udp.ip_header).to be_a(IPHeader)
      expect(udp.ipv6_header).to be_nil
    end

    it "should allow re-reading" do
      udp_packet = PacketFu::UDPPacket.new
      udp_packet2 = Packet.parse(udp_packet.to_s)

      expect(udp_packet).to be_kind_of(UDPPacket)
      expect(udp_packet2).to be_kind_of(UDPPacket)
      expect(udp_packet.is_udp?).to be(true)
      expect(udp_packet2.is_udp?).to be(true)
    end

    it "should create UDP on IPv6 packets" do
      udp = UDPPacket.new(:on_ipv6 => true)
      expect(udp.ip_header).to be_nil
      expect(udp.ipv6_header).to be_a(IPv6Header)

      udp.ipv6_saddr = "::1"
      udp.ipv6_daddr = "::2"
      udp.udp_src = 41000
      udp.udp_dst = 42000
      udp.payload = "\0" * 16
      udp.recalc
      expect(udp.udp_sum).to eq(0xbb82)
      expect(udp.udp_len).to eq(24)
    end

    it 'should support peek functionnality (IPv4 case)' do
      udp = UDPPacket.new
      udp.ip_saddr = '192.168.1.1'
      udp.ip_daddr = '192.168.1.254'
      udp.udp_src = 32756
      udp.udp_dst = 80
      udp.payload = 'abcdefghijklmnopqrstuvwxyz'
      udp.recalc
      expect(udp.peek).to match(/U  68\s+192.168.1.1:32756\s+->\s+192.168.1.254:80/)
    end

    it 'should support peek functionnality (IPv6 case)' do
      udp = UDPPacket.new(:on_ipv6 => true)
      udp.ipv6_saddr = '2000::1'
      udp.ipv6_daddr = '2001::1'
      udp.udp_src = 32756
      udp.udp_dst = 80
      udp.payload = 'abcdefghijklmnopqrstuvwxyz'
      udp.recalc
      expect(udp.peek).to match(/6U 88\s+2000::1:32756\s+->\s+2001::1:80/)
    end
  end

  context "when reading UDPPacket from string" do
    it "should create UDPPacket and strip extra bytes" do
      str = "01005e7ffffa100ba9eb63400800450000a12d7c0000011159b446a5fb7ceffffffacdf3076c008d516e4d2d534541524348202a20485454502f312e310d0a486f73743a3233392e3235352e3235352e3235303a313930300d0a53543a75726e3a736368656d61732d75706e702d6f72673a6465766963653a496e7465726e6574476174657761794465766963653a310d0a4d616e3a22737364703a646973636f766572220d0a4d583a330d0a0d0a".bin
      str << "0102".bin # Tacking on a couple extra bytes tht we'll strip off.
      not_stripped = UDPPacket.new
      not_stripped.read(str)
      expect(not_stripped.udp_header.body.length).to eql(135)

      stripped = UDPPacket.new
      stripped.read(str, :strip => true)
      expect(stripped.udp_header.body.length).to eql(133)
    end
  end

end
