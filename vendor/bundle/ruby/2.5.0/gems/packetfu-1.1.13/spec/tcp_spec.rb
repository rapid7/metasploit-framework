require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/tcp'
require 'packetfu/pcap'

include PacketFu

def unusual_numeric_handling_headers(header,i)
  camelized_header = header.to_s.split("_").map {|x| x.capitalize}.join
  header_class = PacketFu.const_get camelized_header
  specify { subject.send(header).should == i }
  specify { subject.send(header).should be_kind_of Integer }
  specify { subject.headers.last[header].should be_kind_of header_class }
end

def tcp_hlen_numeric(i)
  unusual_numeric_handling_headers(:tcp_hlen,i)
end

def tcp_reserved_numeric(i)
  unusual_numeric_handling_headers(:tcp_reserved,i)
end

def tcp_ecn_numeric(i)
  unusual_numeric_handling_headers(:tcp_ecn,i)
end


describe TCPPacket do

  subject do
    bytes = PcapFile.file_to_array(File.join(File.dirname(__FILE__), "sample2.pcap"))[2]
    packet = Packet.parse(bytes)
  end

  context "TcpHlen reading and setting" do
    context "TcpHlen set via #read" do
      tcp_hlen_numeric(8)
    end
    context "TcpHlen set via an Integer for the setter" do
      (0..15).each do |i|
        context "i is #{i}" do
          before { subject.tcp_hlen = i }
          tcp_hlen_numeric(i)
        end
      end
    end
    context "TcpHlen set via a String for the setter" do
      before { subject.tcp_hlen = "\x60" }
      tcp_hlen_numeric(6)
    end
    context "TcpHlen set via a TcpHlen for the setter" do
      before { subject.tcp_hlen = TcpHlen.new(:hlen => 7) }
      tcp_hlen_numeric(7)
    end
  end

  context "TcpReserved reading and setting" do
    context "TcpReserved set via #read" do
      tcp_reserved_numeric(0)
    end
    context "TcpReserved set via an Integer for the setter" do
      (0..7).each do |i|
        context "i is #{i}" do
          before { subject.tcp_reserved = i }
          tcp_reserved_numeric(i)
        end
      end
    end
    context "TcpReserved set via a String for the setter" do
      before { subject.tcp_reserved = "\x03" }
      tcp_reserved_numeric(3)
    end
    context "TcpReserved set via a TcpReserved for the setter" do
      before { subject.tcp_reserved = TcpReserved.new(:r1 => 1, :r2 => 0, :r3 => 1) }
      tcp_reserved_numeric(5)
    end
  end

  context "TcpEcn reading and setting" do
    context "TcpEcn set via #read" do
      tcp_ecn_numeric(0)
    end
    context "TcpEcn set via an Integer for the setter" do
      (0..7).each do |i|
        context "i is #{i}" do
          before { subject.tcp_ecn = i }
          tcp_ecn_numeric(i)
        end
      end
    end
    context "TcpEcn set via a String for the setter" do
      before { subject.tcp_ecn = "\x00\xc0" }
      tcp_ecn_numeric(3)
    end
    context "TcpEcn set via a TcpEcn for the setter" do
      before { subject.tcp_ecn = TcpEcn.new(:n => 1, :c => 0, :e => 1) }
      tcp_ecn_numeric(5)
    end
  end

end
