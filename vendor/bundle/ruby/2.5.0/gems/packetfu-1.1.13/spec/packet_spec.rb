require 'spec_helper'
require 'packetfu/packet'
require 'packetfu/pcap'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/tcp'
require 'packetfu/protos/icmp'
require 'fake_packets'

describe PacketFu::Packet, "abstract packet class behavior" do

  before(:all) do
    add_fake_packets
  end

  after(:all) do
    remove_fake_packets
  end

  it "should not be instantiated" do
    expect { PacketFu::Packet.new }.to raise_error(NoMethodError)
  end

  it "should allow subclasses to instantiate" do
    expect(PacketFu::FooPacket.new).to be
    PacketFu.packet_classes.include?(PacketFu::FooPacket).should be true
  end

  it "should register packet classes with PacketFu" do
    PacketFu.packet_classes {should include(FooPacket) }
    PacketFu.packet_classes {should include(BarPacket) }
  end

  it "should disallow badly named subclasses" do
    expect {
      class PacketFu::PacketNot < PacketFu::Packet
      end
    }.to raise_error(RuntimeError, "Packet classes should be named 'ProtoPacket'")
    PacketFu.packet_classes.include?(PacketFu::PacketNot).should be false
    PacketFu.packet_classes {should_not include(PacketNot) }
  end

  before(:each) do
    @tcp_packet = PacketFu::TCPPacket.new
    @tcp_packet.ip_saddr = "10.10.10.10"
  end

  it "should shallow copy with dup()" do
    p2 = @tcp_packet.dup
    p2.ip_saddr = "20.20.20.20"
    p2.ip_saddr.should == @tcp_packet.ip_saddr
    p2.headers[1].object_id.should == @tcp_packet.headers[1].object_id
  end

  it "should deep copy with clone()" do
    p3 = @tcp_packet.clone
    p3.ip_saddr = "30.30.30.30"
    p3.ip_saddr.should_not == @tcp_packet.ip_saddr
    p3.headers[1].object_id.should_not == @tcp_packet.headers[1].object_id
  end

  it "should have senisble equality" do
    p4 = @tcp_packet.dup
    p4.should == @tcp_packet
    p5 = @tcp_packet.clone
    p5.should == @tcp_packet
  end

  # It's actually kinda hard to manually create identical TCP packets
  it "should be possible to manually create identical packets" do
    p6 = @tcp_packet.clone
    p6.should == @tcp_packet
    p7 = PacketFu::TCPPacket.new
    p7.ip_saddr = p6.ip_saddr
    p7.ip_id = p6.ip_id
    p7.tcp_seq = p6.tcp_seq
    p7.tcp_src = p6.tcp_src
    p7.tcp_sum = p6.tcp_sum
    p7.should == p6
  end

  it "should parse IPv4 packets" do
    packets = PacketFu::PcapFile.read(File.join(File.dirname(__FILE__), 'ipv4_icmp.pcap'))
    packets.size.should == 1
    packet = PacketFu::Packet.parse(packets.first.data.to_s)
    packet.should be_a(PacketFu::ICMPPacket)
    packet.headers[1].should be_a(PacketFu::IPHeader)
  end

  it "should parse IPv6 packets" do
    packets = PacketFu::PcapFile.read(File.join(File.dirname(__FILE__), 'ipv6_udp.pcap'))
    packets.size.should == 1
    packet = PacketFu::Packet.parse(packets.first.data.to_s)
    packet.should be_a(PacketFu::UDPPacket)
    packet.headers[1].should be_a(PacketFu::IPv6Header)
  end

end
