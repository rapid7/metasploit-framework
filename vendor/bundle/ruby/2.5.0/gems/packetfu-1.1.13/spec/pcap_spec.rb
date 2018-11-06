# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'
require 'tempfile'
require 'digest/md5'

include PacketFu

describe PcapHeader do
  before(:all) do
    @file = File.open("test/sample.pcap") {|f| f.read}
    @file.force_encoding "binary" if @file.respond_to? :force_encoding
    @file_magic = @file[0,4]
    @file_header = @file[0,24]
  end

  context "when initializing" do
    it "should be a good sample file" do
      expect(@file_magic).to eql("\xd4\xc3\xb2\xa1")
    end

    it "should have sane defaults (little)" do
      @pcap_header = PcapHeader.new
      expect(@pcap_header.sz).to eql(24)
      expect(@pcap_header.endian).to eql(:little)
      expect(@pcap_header.magic).to eql(StructFu::Int32le.new(2712847316))
      expect(@pcap_header.ver_major).to eql(StructFu::Int16le.new(2))
      expect(@pcap_header.ver_minor).to eql(StructFu::Int16le.new(4))
      expect(@pcap_header.thiszone).to eql(StructFu::Int32le.new)
      expect(@pcap_header.sigfigs).to eql(StructFu::Int32le.new)
      expect(@pcap_header.snaplen).to eql(StructFu::Int32le.new(65535))
      expect(@pcap_header.network).to eql(StructFu::Int32le.new(1))
      expect(@pcap_header.to_s[0,4]).to eql("\xD4\xC3\xB2\xA1")
      expect(@pcap_header.to_s[0,4]).to eql(@file_magic)
      expect(@pcap_header.to_s[0,24]).to eql("\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x01\x00\x00\x00")
      expect(@pcap_header.to_s[0,24]).to eql(@file_header)
    end

    it "should have sane defaults (big)" do
      @pcap_header = PcapHeader.new(:endian => :big)
      expect(@pcap_header.sz).to eql(24)
      expect(@pcap_header.endian).to eql(:big)
      expect(@pcap_header.magic).to eql(StructFu::Int32be.new(2712847316, :big))
      expect(@pcap_header.ver_major).to eql(StructFu::Int16be.new(2))
      expect(@pcap_header.ver_minor).to eql(StructFu::Int16be.new(4))
      expect(@pcap_header.thiszone).to eql(StructFu::Int32be.new)
      expect(@pcap_header.sigfigs).to eql(StructFu::Int32be.new)
      expect(@pcap_header.snaplen).to eql(StructFu::Int32be.new(65535))
      expect(@pcap_header.network).to eql(StructFu::Int32be.new(1))
      expect(@pcap_header.to_s[0,4]).to eql("\xA1\xB2\xC3\xD4")
      expect(@pcap_header.to_s[0,24]).to eql("\xA1\xB2\xC3\xD4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\x01")
    end

    it "should error on bad endian type" do
      # We want to ensure our endianness is little or big.
      expect{PcapHeader.new(:endian => :just_right)}.to raise_error(ArgumentError)
    end
  end

  context "when reading from string" do
    it "should be a good sample file" do
      @pcap_header = PcapHeader.new()
      @pcap_header.read(@file)
      expect(@pcap_header.to_s).to eql(@file_header)
    end
  end
end

describe Timestamp do
  before(:all) do
    @file = File.open("test/sample.pcap") {|f| f.read}
    @ts = @file[24,8]
  end

  context "when initializing" do
    it "should have sane defaults" do
      expect(Timestamp.new.size).to eql(3)
      expect(Timestamp.new.sz).to eql(8)
    end
  end

  context "when reading" do
    it "should parse from a string" do
      timestamp = Timestamp.new
      timestamp.read(@ts)
      expect(timestamp.to_s).to eql(@ts)
    end
  end
end

describe PcapPacket do
  before(:all) do
    @file = File.open('test/sample.pcap') {|f| f.read}
    @file.force_encoding "binary" if @file.respond_to? :force_encoding
    @header = @file[0,24]
    @packet = @file[24,100] # pkt is 78 bytes + 16 bytes pcap hdr == 94
  end

  context "when initializing" do
    it "should have sane defaults" do
      pcap_packet = PcapPacket.new(:endian => :little)
      expect(pcap_packet.endian).to eql(:little)
      expect(pcap_packet.timestamp).to eql(PacketFu::Timestamp.new(:endian => :little))
      expect(pcap_packet.incl_len).to eql(StructFu::Int32le.new(0))
      expect(pcap_packet.orig_len).to eql(StructFu::Int32le.new)
      expect(pcap_packet.data).to eql("")
    end
  end

  context "when reading" do
    it "should parse from a string" do
      pcap_packet = PcapPacket.new :endian => :little
      pcap_packet.read(@packet)
      expect(pcap_packet.endian).to eql(:little)
      expect(pcap_packet.timestamp).to eql(
        PacketFu::Timestamp.new(
          :endian => :little,
          :sec => 1255289346,
          :usec => 244202
        )
      )
      expect(pcap_packet.incl_len).to eql(StructFu::Int32le.new(78))
      expect(pcap_packet.orig_len).to eql(StructFu::Int32le.new(78))
      expect(pcap_packet.data).to eql(
        "\x00\x03/\x1At\xDE\x00\e\x11Q\xB7\xCE\b\x00E\x00\x00@\"" +
        "\xB4\x00\x00\x80\x11\x94=\xC0\xA8\x01i\xC0\xA8\x01\x02" +
        "\xD7\xDD\x005\x00,\x8B\xF8\xA6?\x01\x00\x00\x01\x00\x00" +
        "\x00\x00\x00\x00\x03www\nmetasploit\x03com\x00\x00\x01" +
        "\x00\x01"
      )

      expect(pcap_packet[:incl_len].to_i).to eql(78)
      expect(pcap_packet.to_s).to eql(@packet[0,94])
    end
  end
end

describe PcapPackets do
  before(:all) do
    @file = File.open('test/sample.pcap') {|f| f.read}
  end

  context "when initializing" do
    it "should have sane defaults" do
      pcap_packets = PcapPackets.new()
      expect(pcap_packets.endian).to eql(:little)
      expect(pcap_packets.size).to eql(0)
      expect(pcap_packets).to be_kind_of(Array)
    end
  end

  context "when reading" do
    it "should have read pcap packets" do
      pcap_packets = PcapPackets.new()
      pcap_packets.read @file
      expect(pcap_packets.size).to eql(11)
      expect(pcap_packets.size).to eql(11)
      expect(pcap_packets.to_s).to eql(@file[24,@file.size])
    end
  end
end

describe PcapFile do
  before(:all) do
    @file = File.open('test/sample.pcap') {|f| f.read}
    @md5 = '1be3b5082bb135c6f22de8801feb3495'
  end

  context "when initializing" do
    it "should have sane defaults" do
      pcap_file = PcapFile.new()
      expect(pcap_file.endian).to eql(nil)
      expect(pcap_file.head).to eql(PcapHeader.new)
      expect(pcap_file.body).to eql(PcapPackets.new)
    end
  end

  context "when reading and writing" do
    before(:each) { @temp_file = Tempfile.new('pcap_pcap') }
    after(:each) { @temp_file.close; @temp_file.unlink }

    it "should read via #read and write via #to_file" do
      pcap_file = PcapFile.new
      pcap_file.read @file
      pcap_file.to_file(:filename => @temp_file.path)
      newfile = File.open(@temp_file.path) {|f| f.read(f.stat.size)}
      newfile.force_encoding "binary" if newfile.respond_to? :force_encoding
      expect(newfile).to eql(@file)

      pcap_file.to_file(:filename => @temp_file.path, :append => true)
      packet_array = PcapFile.new.f2a(:filename => @temp_file.path)
      expect(packet_array.size).to eql(22)
    end

    it "should read via #file_to_array and write via #to_f" do
      # TODO: Figure out why this is failing to write properly when converted to a Tempfile
      File.unlink('out.pcap') if File.exists? 'out.pcap'
      pcaps = PcapFile.new.file_to_array(:filename => 'test/sample.pcap')
      pcaps.each {|pkt|
        packet = Packet.parse pkt
        packet.recalc
        packet.to_f('out.pcap','a')
      }
      packet_array = PcapFile.new.f2a(:filename => 'out.pcap')
      expect(packet_array.size).to eql(11)
      File.unlink('out.pcap')
    end

    it "should read via #file_to_array and write via #a2f with timestamp changes" do
      pcap_file = PcapFile.new
      packet_array = pcap_file.file_to_array(:filename => 'test/sample.pcap')
      expect(packet_array.size).to eql(11)

      pcap_file = PcapFile.new
      pcap_file.a2f(:array => packet_array, :f => @temp_file.path, :ts_inc => 4,
             :timestamp => Time.now.to_i - 1_000_000)
      diff_time = pcap_file.body[0].timestamp.sec.to_i - pcap_file.body[1].timestamp.sec.to_i
      expect(diff_time).to eql(-4)

      packet_array_2 = pcap_file.file_to_array(:filename => @temp_file.path)
      expect(packet_array_2.size).to eql(11)
    end
  end

end

describe Read do
  context "when initializing" do
    it "should have sane defaults" do
      pcap_packets = Read.new()
      expect(pcap_packets).to be_kind_of(Read)
    end
  end

  context "when reading" do
    it "should read from a string" do
      pkts = Read.file_to_array(:file => 'test/sample.pcap')
      expect(pkts).to be_kind_of(Array)
      expect(pkts.size).to eql(11)

      this_packet = Packet.parse pkts[0]
      expect(this_packet).to be_kind_of(UDPPacket)

      that_packet = Packet.parse pkts[3]
      expect(that_packet).to be_kind_of(ICMPPacket)
    end

    it "should read from a hash" do
      pkts = Read.file_to_array(:file => 'test/sample.pcap', :ts => true)
      expect(pkts).to be_kind_of(Array)
      expect(pkts.size).to eql(11)

      this_packet = Packet.parse pkts[0].values.first
      expect(this_packet).to be_kind_of(UDPPacket)

      that_packet = Packet.parse pkts[3].values.first
      expect(that_packet).to be_kind_of(ICMPPacket)
    end
  end
end

describe Write do
  context "when initializing" do
    it "should have sane defaults" do
      pcap_packets = Write.new()
      expect(pcap_packets).to be_kind_of(Write)
    end
  end

  context "when writing" do
    before(:each) { @temp_file = Tempfile.new('write_pcap') }
    after(:each) { @temp_file.close; @temp_file.unlink }

    it "should read from a string" do
      pkts = Read.file_to_array(:file => 'test/sample.pcap')
      expect(pkts).to be_kind_of(Array)
      expect(pkts.size).to eql(11)

      Write.array_to_file(:array => pkts, :file => @temp_file.path)

      pkts_new = Read.file_to_array(:file => @temp_file.path)
      expect(pkts).to be_kind_of(Array)
      expect(pkts.size).to eql(11)
    end
  end
end
