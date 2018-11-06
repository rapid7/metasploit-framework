require 'spec_helper'
require 'packetfu'
require 'packetfu/protos/lldp'

include PacketFu

describe LLDPPacket do
  context "when initializing LLDPPacket" do
    it "should have sane defaults" do
      lldp_packet = LLDPPacket.new
      expect(lldp_packet).to be_kind_of(LLDPPacket)
    end
  end

  context "when reading" do
    it "should read from PCAP and detect LLDP packets" do
      cap = PacketFu::PcapFile.new.file_to_array(:filename => "./test/sample_lldp.pcap")

      lldap_packet1 = PacketFu::Packet.parse(cap[0])
      expect(lldap_packet1).to be_kind_of(LLDPPacket)
      expect(lldap_packet1.is_lldp?).to be(true)
      expect(lldap_packet1.proto.last).to eql("LLDP")
      expect(lldap_packet1.lldp_capabilty).to eql("0x0080")
      expect(lldap_packet1.lldp_address_type_readable).to eql("IPv4")
      expect(lldap_packet1.lldp_address).to eql("lldp_address")
      expect(lldap_packet1.lldp_interface_type).to eql(2)
      expect(lldap_packet1.lldp_interface).to eql(0)

      lldap_packet2 = PacketFu::Packet.parse(cap[1])
      expect(lldap_packet2).to be_kind_of(LLDPPacket)

      lldap_packet3 = PacketFu::Packet.parse(cap[2])
      expect(lldap_packet3).to be_kind_of(LLDPPacket)
    end
  end
end
