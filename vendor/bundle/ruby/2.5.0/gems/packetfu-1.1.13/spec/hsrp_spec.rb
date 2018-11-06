# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

include PacketFu

context "when parsing HSRP traffic from pcap" do
  it "should detect that it's HSRP traffic" do
    sample_packet = PcapFile.new.file_to_array(:f => 'test/sample_hsrp_pcapr.cap')[0]
    pkt = Packet.parse(sample_packet)
    expect(pkt.is_hsrp?).to be(true)
    expect(pkt.is_udp?).to be(true)
    expect(pkt.udp_sum.to_i).to eql(0x2d8d)
  end
end
