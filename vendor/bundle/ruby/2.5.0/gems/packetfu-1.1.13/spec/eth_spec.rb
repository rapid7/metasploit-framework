# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/tcp'
require 'packetfu/pcap'
require 'tempfile'

include PacketFu

describe EthMac do
  context "when creating an object from scratch" do
    before :each do
      @eth_mac = EthMac.new
    end

    it "should have sane defaults" do
      expect(@eth_mac.oui).to be_kind_of(EthOui)
      expect(@eth_mac.oui.oui).to eql(428)
      expect(@eth_mac.nic).to be_kind_of(EthNic)
      expect(@eth_mac.nic.to_s).to eql("\x00\x00\x00")
    end
  end

  context "when parsing EthMac from the wire" do
    before :each do
      @eth_mac = EthMac.new
    end

    it "should parse from string i/o (Example 1)" do
      dst = "\x00\x03\x2f\x1a\x74\xde"
      @eth_mac.read(dst)

      expect(@eth_mac).to be_kind_of(EthMac)
      expect(@eth_mac.to_s).to eql(dst)
      expect(@eth_mac.oui.oui).to eql(0x32f)
      expect(@eth_mac.nic.to_s).to eql("\x1At\xDE".force_encoding('binary'))
      expect(@eth_mac.nic.n2).to eql(222)
    end

    it "should parse from an ipad" do
      dst = "\x7c\x6d\x62\x01\x02\x03"
      @eth_mac.read(dst)

      expect(@eth_mac).to be_kind_of(EthMac)
      expect(@eth_mac.to_s).to eql(dst)
      expect(@eth_mac.oui.oui).to eql(0x6d62)
    end
  end

end

describe EthHeader do
  context "when creating an object from scratch" do
    before :each do
      @eth_header = EthHeader.new
    end

    it "should have sane defaults" do
      expect(@eth_header).to be_kind_of(EthHeader)
      expect(@eth_header.eth_src).to eql("\x00\x01\xAC\x00\x00\x00".force_encoding('binary'))
      expect(@eth_header.eth_dst).to eql("\x00\x01\xAC\x00\x00\x00".force_encoding('binary'))
      expect(@eth_header.eth_proto).to eql(2048)
    end

    it "should allow setting of the dstmac" do
      dst = "\x00\x03\x2f\x1a\x74\xde"
      dstmac = "00:03:2f:1a:74:de"

      expect(EthHeader.str2mac(dst)).to eql(dstmac)
      expect(EthHeader.mac2str(dstmac)).to eql(dst)
    end
  end
end

describe EthPacket do
  context "when creating an object from scratch" do
    before :each do
      @eth_packet = EthPacket.new
    end

    it "should have sane defaults" do
      expect(@eth_packet.eth_dst).to eql("\x00\x01\xAC\x00\x00\x00")
      expect(@eth_packet.eth_src).to eql("\x00\x01\xAC\x00\x00\x00")
      expect(@eth_packet.eth_proto).to eql(2048)
    end

    it "should be able to match a predefined eth_packet via string i/o" do
      raw_header = "00032f1a74de001b1151b7ce0800".scan(/../).map { |x| x.to_i(16) }.pack("C*")

      expect(@eth_packet).to be_kind_of(EthPacket)
      expect(@eth_packet.headers[0]).to be_kind_of(EthHeader)
      expect(@eth_packet.is_eth?).to be true
      expect(@eth_packet.is_tcp?).to be false

      @eth_packet.eth_dst = "\x00\x03\x2f\x1a\x74\xde"
      @eth_packet.eth_src = "\x00\x1b\x11\x51\xb7\xce"
      @eth_packet.eth_proto = 0x0800

      expect(@eth_packet.to_s[0,14]).to eql(raw_header)
    end

    it "should be able to match a predefined eth_packet via opts" do
      raw_header = "00032f1a74de001b1151b7ce0800".scan(/../).map { |x| x.to_i(16) }.pack("C*")

      @eth_packet = EthPacket.new(
                      :eth_dst => "\x00\x03\x2f\x1a\x74\xde",
                      :eth_src => "\x00\x1b\x11\x51\xb7\xce",
                      :eth_proto => 0x0800
                    )

      expect(@eth_packet.to_s[0,14]).to eql(raw_header)
    end
  end

  context "when reading/writing PCAP to file" do
    before(:each) { @temp_file = Tempfile.new('arp_pcap') }
    after(:each) { @temp_file.close; @temp_file.unlink }


    it "should write a pcap file to disk" do
      @eth_packet = EthPacket.new(
                      :eth_dst => "\x00\x03\x2f\x1a\x74\xde",
                      :eth_src => "\x00\x1b\x11\x51\xb7\xce",
                      :eth_proto => 0x0800
                    )

      @eth_packet.recalc
      expect(@temp_file.read).to eql("")

      @eth_packet.to_f(@temp_file.path, 'a')
      expect(File.exists?(@temp_file.path))
      expect(@temp_file.read.size).to be >= 30
    end

    it "should read a pcap file to create ethpacket" do
      parsed_packets = PcapFile.read_packets("./test/sample.pcap")
      @eth_packet = parsed_packets.first

      expect(@eth_packet).to be_kind_of(EthPacket)
      expect(@eth_packet.eth_daddr).to eql("00:03:2f:1a:74:de")
      expect(@eth_packet.eth_saddr).to eql("00:1b:11:51:b7:ce")
      expect(@eth_packet.size).to eql(78)
      expect(@eth_packet.headers.first.body).to be_kind_of(PacketFu::IPHeader)
      expect(@eth_packet.headers.first.members).to eql([:eth_dst, :eth_src, :eth_proto, :body])
    end

    # TODO: Figure out why this is failing
    # it "should read a vlan encapsulated ethpacket as an invalid packet" do
    #   parsed_packets = PcapFile.read_packets("./test/vlan-pcapr.cap")
    #   @eth_packet = parsed_packets.first
    #
    #   expect(@eth_packet).to be_kind_of(InvalidPacket)
    # end
  end
end
