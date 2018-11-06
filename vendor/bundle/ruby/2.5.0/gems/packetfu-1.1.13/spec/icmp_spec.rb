# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/icmp'
require 'packetfu/pcap'
require 'tempfile'

include PacketFu

describe ICMPPacket, "when read from a pcap file" do
  before :all do
      parsed_packets = PcapFile.read_packets(File.join(File.dirname(__FILE__),"sample.pcap"))
      @icmp_packet = parsed_packets[3]

      parsed_packets3 = PcapFile.read_packets(File.join(File.dirname(__FILE__),"sample3.pcap"))
      @icmp_packet2 = parsed_packets3[8] # contains 0x0A byte in payload
  end

  it "should be recognized as an icmp packet" do
      @icmp_packet.is_icmp?.should be true
  end

  it "should report the right seq number" do
    @icmp_packet.payload[2..3].unpack("H*")[0].should eq "0003"
  end

  it "should be recognized as an icmp reply packet" do
      @icmp_packet.icmp_type.should eq 0
  end

  it "should have the right checksum" do
    @icmp_packet.icmp_sum.to_s(16).should eq @icmp_packet.icmp_calc_sum.to_s(16)
  end

  it "should have the right checksum even with 0xOA byte in payload" do
    @icmp_packet2.icmp_sum.to_s(16).should eq @icmp_packet2.icmp_calc_sum.to_s(16)
  end

  context "when initializing ICMPHeader from scratch" do
    before :each do
      @icmp_header = ICMPHeader.new
    end

    it "should have the right instance variables" do
      expect(@icmp_header.to_s).to eql("\x00\x00\xff\xff")
      expect(@icmp_header.icmp_type).to eql(0)
    end

    it "should allow setting of the type" do
      @icmp_header.icmp_type = 1
      expect(@icmp_header.icmp_type).to eql(1)
      @icmp_header.icmp_recalc
      expect(@icmp_header.to_s).to eql("\x01\x00\xfe\xff")
    end
  end

  context "when initializing ICMPPacket from scratch" do
    before :each do
      @icmp_packet = ICMPPacket.new
    end

    it "should support peak functionality" do
      @icmp_packet.ip_saddr = "10.20.30.40"
      @icmp_packet.ip_daddr = "50.60.70.80"
      @icmp_packet.payload = "abcdefghijklmnopqrstuvwxyz"
      @icmp_packet.recalc
      expect(@icmp_packet.peek).to match(/IC 64\s+10.20.30.40:pong\s+->\s+50.60.70.80\s+I:[a-z0-9]{4}/)
    end
  end

  context "when reading/writing ICMPPacket to disk" do
    before :each do
      @icmp_packet = ICMPPacket.new
      @temp_file = Tempfile.new('icmp_pcap')
    end

    after(:each) { @temp_file.close; @temp_file.unlink }

    it "should write a PCAP file to disk" do
      @icmp_packet.ip_saddr = "10.20.30.40"
      @icmp_packet.ip_daddr = "50.60.70.80"
      @icmp_packet.payload = "abcdefghijklmnopqrstuvwxyz"
      @icmp_packet.recalc

      expect(@temp_file.read).to eql("")

      @icmp_packet.to_f(@temp_file.path, 'a')
      expect(File.exists?(@temp_file.path))
      expect(@temp_file.read.size).to be >= 79
    end

    it "should read a PCAP file from disk" do
      sample_packet = PcapFile.new.file_to_array(:f => './test/sample.pcap')[2]
      pkt = Packet.parse(sample_packet)

      expect(pkt.is_icmp?).to be true
      expect(pkt.class).to eql(PacketFu::ICMPPacket)
      expect(pkt.icmp_sum.to_i).to eql(0x4d58)
      expect(pkt.icmp_type.to_i).to eql(8)
    end
  end
end
