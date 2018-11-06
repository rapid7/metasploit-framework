require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/tcp'
require 'packetfu/version'
require 'fake_packets'

describe PacketFu, "version information" do
  it "reports a version number" do
    PacketFu::VERSION.should match /^1\.[0-9]+\.[0-9]+(.pre)?$/
  end
  its(:version) {should eq PacketFu::VERSION}

  it "can compare version strings" do
    PacketFu.binarize_version("1.2.3").should == 0x010203
    PacketFu.binarize_version("3.0").should == 0x030000
    PacketFu.at_least?("1.0").should be true
    PacketFu.at_least?("4.0").should be false
    PacketFu.older_than?("4.0").should be true
    PacketFu.newer_than?("1.0").should be true
  end

  it "can handle .pre versions" do
    PacketFu.binarize_version("1.7.6.pre").should == 0x010706
    PacketFu.at_least?("0.9.0.pre").should be true
  end
end

describe PacketFu, "instance variables" do
  it "should have a bunch of instance variables" do
    PacketFu.instance_variable_get(:@byte_order).should == :little
    PacketFu.instance_variable_get(:@pcaprub_loaded).should_not be_nil
  end
end

describe PacketFu, "pcaprub deps" do
  it "should check for pcaprub" do
    begin
      has_pcap = false
      require 'pcaprub'
      has_pcap = true
    rescue LoadError
    end
    if has_pcap
      PacketFu.instance_variable_get(:@pcaprub_loaded).should be true
    else
      PacketFu.instance_variable_get(:@pcaprub_loaded).should be false
    end
  end
end

describe PacketFu, "protocol requires" do
  it "should have some protocols defined" do
    PacketFu::EthPacket.should_not be_nil
    PacketFu::IPPacket.should_not be_nil
    PacketFu::TCPPacket.should_not be_nil
    expect { PacketFu::FakePacket }.to raise_error(NameError, /uninitialized constant PacketFu::FakePacket/)
  end
end

describe PacketFu, "packet class list management" do

  it "should allow packet class registration" do
    PacketFu.add_packet_class(PacketFu::FooPacket).should be_kind_of Array
    PacketFu.add_packet_class(PacketFu::BarPacket).should be_kind_of Array
  end

  its(:packet_classes) {should include(PacketFu::FooPacket)}

  it "should disallow non-classes as packet classes" do
    expect { PacketFu.add_packet_class("A String") }.to raise_error(RuntimeError, "Need a class")
  end

  its(:packet_prefixes) {should include("bar")}

  # Don't really have much utility for this right now.
  it "should allow packet class deregistration" do
    PacketFu.remove_packet_class(PacketFu::BarPacket)
    PacketFu.packet_prefixes.should_not include("bar")
    PacketFu.add_packet_class(PacketFu::BarPacket)
  end

end
