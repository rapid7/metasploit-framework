require 'spec_helper'
require 'tempfile'
require 'packetfu/protos/ip'

include PacketFu

describe Octets do
  context "when initializing" do
    before :each do
      @octets = Octets.new
    end

    it "should have sane defaults" do
      expect(@octets.to_x).to eql("0.0.0.0")
    end
  end

  context "when reading from the wire" do
    before :each do
      @octets = Octets.new
    end

    it "should #read from string i/o" do
      @octets.read("\x04\x03\x02\x01")
      expect(@octets.to_x).to eql("4.3.2.1")
    end

    it "should #read_quad from string i/o" do
      @octets.read_quad("1.2.3.4")
      expect(@octets.to_x).to eql("1.2.3.4")
      expect(@octets.to_s).to eql("\x01\x02\x03\x04")
      expect(@octets.to_i).to eql(0x01020304)
    end

    it "should #read from string i/o (single octet)" do
      @octets.read("ABCD")
      expect(@octets.o1).to eql(0x41)
      expect(@octets.o2).to eql(0x42)
      expect(@octets.o3).to eql(0x43)
      expect(@octets.o4).to eql(0x44)
    end
  end
end
