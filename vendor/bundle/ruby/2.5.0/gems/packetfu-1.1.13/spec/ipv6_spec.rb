require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/pcap'

include PacketFu

describe IPv6Header do
  context "when initializing an IPv6Header" do
    before :each do
      @ipv6_header = IPv6Header.new
    end

    it "should contain sane defaults" do
      expect(@ipv6_header.ipv6_v).to eql(6)
      expect(@ipv6_header.ipv6_len).to eql(0)
      expect(@ipv6_header.ipv6_src).to eql(0)
      expect(@ipv6_header.ipv6_dst).to eql(0)
      expect(@ipv6_header.ipv6_hop).to eql(255)
      expect(@ipv6_header.ipv6_next).to eql(0)
    end
  end
end

describe AddrIpv6 do
  context "when parsing IPv6 from wire" do
    before :each do
      @address_ipv6 = AddrIpv6.new
    end

    it "should parse an IPv6 address from string i/o" do
      raw_addr_ipv6 = "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x1a\xc5\xff\xfe\x00\x01\x52"
      @address_ipv6.read(raw_addr_ipv6)

      expect(@address_ipv6.to_i).to eql(338288524927261089654170548082086773074)
      expect(@address_ipv6.to_x).to eql("fe80::21a:c5ff:fe00:152")
    end

    it "should parse an IPv6 address from octet string" do
      ipv6_string = "fe80::21a:c5ff:fe00:152"
      @address_ipv6.read_x(ipv6_string)

      expect(@address_ipv6.to_x).to eql(ipv6_string)
    end
  end
end

describe IPv6Packet do
  context "when initializing an IPv6Packet" do
    before :each do
      @ipv6_packet = IPv6Packet.new
    end

    it "should contain sane defaults" do
      expect(@ipv6_packet.ipv6_v).to eql(6)
      expect(@ipv6_packet.payload).to eql("")
      expect(@ipv6_packet.is_ipv6?).to be true
    end

    it "should support peek functionality" do
      expect(@ipv6_packet.peek).to match(/6\s+54\s+::\s+\->\s+::\s+N:0/)
    end

    it 'should set payload size on #recalc' do
      @ipv6_packet.payload = "\0" * 14
      @ipv6_packet.recalc
      expect(@ipv6_packet.ipv6_len).to eq(14)

      @ipv6_packet.payload = "\0" * 255
      @ipv6_packet.recalc(:ipv6)
      expect(@ipv6_packet.ipv6_len).to eq(255)
    end

    it 'should set payload size on #ipv6_recalc' do
      @ipv6_packet.payload = "\0" * 3
      @ipv6_packet.ipv6_recalc
      expect(@ipv6_packet.ipv6_len).to eq(3)

      @ipv6_packet.payload = "\xff" * 12
      @ipv6_packet.ipv6_recalc(:ipv6_len)
      expect(@ipv6_packet.ipv6_len).to eq(12)
    end
  end
end
