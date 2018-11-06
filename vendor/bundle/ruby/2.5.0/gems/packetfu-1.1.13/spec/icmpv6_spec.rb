# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/icmpv6'
require 'packetfu/pcap'
require 'tempfile'

include PacketFu

describe ICMPv6Packet, "when read from a pcap file" do
  before(:all) do
    parsed_packets = PcapFile.read_packets(File.join(File.dirname(__FILE__),
                                                     "ipv6_icmp.pcap"))
    @icmpv6_packet = parsed_packets.first
  end

  it 'should be recognized as an icmp packet' do
    expect(@icmpv6_packet.is_icmpv6?).to be(true)
  end

  it "should report the right seq number" do
    expect(@icmpv6_packet.payload[2..3].unpack("H*")[0]).to eq("0001")
  end

  it "should be recognized as an icmp reply packet" do
    expect(@icmpv6_packet.icmpv6_type).to eq(128)
  end

  it "should have the right checksum" do
    expect(@icmpv6_packet.icmpv6_sum.to_s(16)).to eq(@icmpv6_packet.icmpv6_calc_sum.to_s(16))
  end


  context "when initializing ICMPv6Header from scratch" do
    before :each do
      @icmpv6_header = ICMPv6Header.new
    end

    it "should have the right instance variables" do
      expect(@icmpv6_header.to_s).to eql("\x00\x00\x00\x00")
      expect(@icmpv6_header.icmpv6_type).to eql(0)
    end

    it "should allow setting of the type" do
      @icmpv6_header.icmpv6_type = 1
      expect(@icmpv6_header.icmpv6_type).to eql(1)
    end
  end

  context "when initializing ICMPv6Packet from scratch" do
    before :each do
      @icmpv6_packet = ICMPv6Packet.new
    end

    it "should support peak functionality" do
      @icmpv6_packet.ipv6_saddr = "::1:1020:3040"
      @icmpv6_packet.ipv6_daddr = "::1:5060:7080"
      @icmpv6_packet.icmpv6_type = 129
      @icmpv6_packet.payload = "abcdefghijklmnopqrstuvwxyz"
      @icmpv6_packet.recalc
      expect(@icmpv6_packet.peek).to match(/6C 84\s+::1:1020:3040:pong\s+->\s+::1:5060:7080/)
    end
  end

  context "when reading/writing ICMPv6Packet to disk" do
    before :each do
      @icmpv6_packet = ICMPv6Packet.new
      @temp_file = Tempfile.new('icmpv6_pcap')
    end

    after(:each) { @temp_file.close; @temp_file.unlink }

    it "should write a PCAP file to disk" do
      @icmpv6_packet.ipv6_saddr = "::1:1020:3040"
      @icmpv6_packet.ipv6_daddr = "::1:5060:7080"
      @icmpv6_packet.payload = "abcdefghijklmnopqrstuvwxyz"
      @icmpv6_packet.recalc

      expect(@temp_file.read).to eql("")

      @icmpv6_packet.to_f(@temp_file.path, 'a')
      expect(File.exists?(@temp_file.path))
      expect(@temp_file.read.size).to be >= 79
    end

    it "should read a PCAP file from disk" do
      sample_packet = PcapFile.new.file_to_array(:f => './spec/ipv6_icmp.pcap').first
      pkt = Packet.parse(sample_packet)

      expect(pkt.is_icmpv6?).to be true
      expect(pkt.class).to eql(PacketFu::ICMPv6Packet)
      expect(pkt.icmpv6_sum.to_i).to eql(0x24a5)
      expect(pkt.icmpv6_type.to_i).to eql(128)
    end
  end

end
