# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/arp'
require 'packetfu/protos/ip'
require 'packetfu/pcap'
require 'tempfile'

include PacketFu

describe ARPHeader do
  context "when initializing ARPHeader" do
    before :each do
      @arp_header = ARPHeader.new
    end

    it "should have the correct classes for initialization values" do
      expect(@arp_header).to be_kind_of(ARPHeader)
      expect(@arp_header[:arp_hw]).to be_kind_of(StructFu::Int16)
      expect(@arp_header.arp_hw).to be_kind_of(Integer)
      expect(@arp_header[:arp_src_ip]).to be_kind_of(Octets)
      expect(@arp_header.arp_src_ip).to be_kind_of(String)
      expect(@arp_header[:arp_dst_mac]).to be_kind_of(EthMac)
      expect(@arp_header.body).to be_kind_of(StructFu::String)
    end
  end

  context "when parsing ARPHeader from the wire" do
    before :each do
      @arp_header = ARPHeader.new
    end

    it "should be able to parse an ARPHeader from string I/O" do
      hexified_arp_header = "000108000604000200032f1a74dec0a80102001b1151b7cec0a80169"
      raw_arp_header = hexified_arp_header.scan(/../).map {|x| x.to_i(16)}.pack("C*")

      @arp_header.read(raw_arp_header)
      expect(@arp_header.to_s).to eql(raw_arp_header)
      expect(@arp_header.arp_daddr_ip).to eql("192.168.1.105")
      expect(@arp_header.arp_saddr_ip).to eql("192.168.1.2")
      expect(@arp_header.arp_daddr_mac).to eql("00:1b:11:51:b7:ce")
      expect(@arp_header.arp_saddr_mac).to eql("00:03:2f:1a:74:de")
    end
  end
end

describe ARPPacket do
  context "when initializing ARPPacket" do
    before :each do
      @arp_packet = ARPPacket.new
    end

    it "should have the correct values for initialization" do
      expect(@arp_packet).to be_kind_of(ARPPacket)
      expect(@arp_packet.arp_saddr_ip).to eql("0.0.0.0")
      expect(@arp_packet.arp_daddr_ip).to eql("0.0.0.0")
      expect(@arp_packet.arp_src_ip).to eql("\x00\x00\x00\x00")
      expect(@arp_packet.arp_dst_ip).to eql("\x00\x00\x00\x00")
    end

    it "should allow setting values at initialization" do
      opts_hash = {
        :arp_hw => 1,
        :arp_proto => 0x0800,
        :arp_opcode => 2,
        :arp_src_ip => "\xc0\xa8\x01\x02"
      }
      arp = ARPPacket.new(opts_hash)

      expect(@arp_packet.arp_hw).to eql(opts_hash[:arp_hw])
      expect(@arp_packet.arp_proto).to eql(opts_hash[:arp_proto])

      # TODO: Fix the bug that is preventing these values from setting
      #expect(@arp_packet.arp_opcode).to eql(opts_hash[:arp_opcode])
      #expect(@arp_packet.arp_src_ip).to eql(opts_hash[:arp_src_ip])
    end

    it "should have the ability to set IP addresses" do
      @arp_packet.arp_saddr_ip = "1.2.3.4"
      @arp_packet.arp_daddr_ip = "5.6.7.8"

      expect(@arp_packet.arp_saddr_ip).to eql("1.2.3.4")
      expect(@arp_packet.arp_daddr_ip).to eql("5.6.7.8")
      expect(@arp_packet.arp_src_ip).to eql("\x01\x02\x03\x04")
      expect(@arp_packet.arp_dst_ip).to eql("\x05\x06\x07\x08")
    end

    it "should support peek formatting" do
      expect(@arp_packet.peek).to match(/A\s+60\s+00:01:ac:00:00:00\(0.0.0.0\)\->00:01:ac:00:00:00\(0\.0\.0\.0\):Requ/)
    end
  end

  context "when setting attributes on ARPPacket" do
    before :each do
      @arp_packet = ARPPacket.new
    end

    it "should allow the setting of IP addresses" do
      @arp_packet.arp_saddr_ip = "1.2.3.4"
      @arp_packet.arp_daddr_ip = "5.6.7.8"

      expect(@arp_packet.arp_saddr_ip).to eql("1.2.3.4")
      expect(@arp_packet.arp_daddr_ip).to eql("5.6.7.8")
      expect(@arp_packet.arp_src_ip).to eql("\x01\x02\x03\x04")
      expect(@arp_packet.arp_dst_ip).to eql("\x05\x06\x07\x08")
    end

    it "should allow the setting of MAC addresses" do
      @arp_packet.arp_saddr_mac = "00:01:02:03:04:05"
      @arp_packet.arp_daddr_mac = "00:06:07:08:09:0a"

      expect(@arp_packet.arp_saddr_mac).to eql("00:01:02:03:04:05")
      expect(@arp_packet.arp_daddr_mac).to eql("00:06:07:08:09:0a")
      expect(@arp_packet.arp_src_mac).to eql("\x00\x01\x02\x03\x04\x05")
      expect(@arp_packet.arp_dst_mac).to eql("\x00\x06\x07\x08\x09\x0a")
    end

    it "should allow the setting of all attributes" do
      hexified_arp_packet = "000108000604000200032f1a74dec0a80102001b1151b7cec0a80169"
      raw_arp_packet = hexified_arp_packet.scan(/../).map {|x| x.to_i(16)}.pack("C*")

      @arp_packet.arp_hw = 1
      @arp_packet.arp_proto = 0x0800
      @arp_packet.arp_hw_len = 6
      @arp_packet.arp_proto_len = 4
      @arp_packet.arp_opcode = 2
      @arp_packet.arp_src_mac = "\x00\x03\x2f\x1a\x74\xde"
      @arp_packet.arp_src_ip = "\xc0\xa8\x01\x02"
      @arp_packet.arp_dst_mac = "\x00\x1b\x11\x51\xb7\xce"
      @arp_packet.arp_dst_ip = "\xc0\xa8\x01\x69"
      @arp_packet.payload = ""
      expect(@arp_packet.to_s[14,0xffff]).to eql(raw_arp_packet)
    end

    context "when setting arp flavors" do
      before :each do
        @arp_packet = ARPPacket.new
      end

      it "should have a sane default" do
        expect(@arp_packet.payload).to eql("\x00" * 18)
      end

      it "should support a Windows flavor" do
        @arp_packet = ARPPacket.new(:flavor => "Windows")
        expect(@arp_packet.payload).to eql("\x00" * 64)
      end

      it "should support a Linux flavor" do
        @arp_packet = ARPPacket.new(:flavor => "Linux")
        expect(@arp_packet.payload.size).to eql(32)
      end

      it "should support a HP Deskjet flavor" do
        @arp_packet = ARPPacket.new(:flavor => :hp_deskjet)
        expect(@arp_packet.payload.size).to eql(18)
      end
    end
  end

  context "when parsing ARPPacket from the wire" do
    before :each do
      @arp_packet = ARPPacket.new
    end

    it "should be able to parse an ARPPacket from string I/O" do
      hexified_arp_packet = "001b1151b7ce00032f1a74de0806000108000604000200032f1a74dec0a80102001b1151b7cec0a80169c0a80169"
      raw_arp_packet = hexified_arp_packet.scan(/../).map {|x| x.to_i(16)}.pack("C*")

      @arp_packet.read(raw_arp_packet)
      expect(@arp_packet.to_s).to eql(raw_arp_packet)
      expect(@arp_packet.payload).to eql("\xC0\xA8\x01i")
      expect(@arp_packet.arp_daddr_ip).to eql("192.168.1.105")
      expect(@arp_packet.arp_saddr_ip).to eql("192.168.1.2")
      expect(@arp_packet.arp_daddr_mac).to eql("00:1b:11:51:b7:ce")
      expect(@arp_packet.arp_saddr_mac).to eql("00:03:2f:1a:74:de")
    end
  end

  context "when writing ARPPacket to PCAP" do
    before :each do
      @arp_packet = ARPPacket.new
      @temp_file = Tempfile.new('arp_pcap')
    end

    after(:each) { @temp_file.close; @temp_file.unlink }

    it "should write a PCAP file to disk" do
      @arp_packet.recalc
      expect(@temp_file.read).to eql("")

      @arp_packet.to_f(@temp_file.path, 'a')
      expect(File.exists?(@temp_file.path)).to be(true)
      expect(@temp_file.read.size).to be >= 76
    end
  end
end
