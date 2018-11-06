# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

include PacketFu

describe InvalidPacket, "when read from a pcap file" do
  context "when initializing" do
    it "should have sane defaults (little)" do
      invalid_packet = InvalidPacket.new
      expect(invalid_packet).to be_kind_of(InvalidPacket)
      expect(invalid_packet).to be_kind_of(Packet)
      expect(invalid_packet.is_invalid?).to be(true)
      expect(invalid_packet.is_eth?).to be(false)
      expect(invalid_packet.class).not_to eql(EthPacket)
    end
  end

  context "when reading" do
    # Sadly, the only way to generate an "InvalidPacket" is
    # to read a packet that's less than 14 bytes. Otherwise,
    # it's presumed to be an EthPacket. TODO: Fix this assumption!
    it "should be an invalid packet" do
      invalid_packet = Packet.parse("A" * 13)
      expect(invalid_packet).to be_kind_of(InvalidPacket)
    end
  end
end
