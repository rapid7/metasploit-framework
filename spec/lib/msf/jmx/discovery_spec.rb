# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/java'
require 'msf/jmx'

describe Msf::Jmx::Discovery do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Jmx
    mod.send(:initialize)
    mod
  end

  let(:stream_discovery) do
    "\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" +
    "\x44\x15\x4d\xc9\xd4\xe6\x3b\xdf\x74\x00\x06\x6a\x6d\x78\x72\x6d" +
    "\x69"
  end

  let(:block_data_answer) do
    "\x00\x0a\x55\x6e\x69\x63\x61\x73\x74\x52\x65\x66\x00\x0e\x31\x37" +
    "\x32\x2e\x31\x36\x2e\x31\x35\x38\x2e\x31\x33\x31\x00\x00\x0b\xf1" +
    "\x54\x74\xc4\x27\xb7\xa3\x4e\x9b\x51\xb5\x25\xf9\x00\x00\x01\x4a" +
    "\xdf\xd4\x57\x7e\x80\x01\x01"
  end

  let(:mbean_server) do
    {
      :address => '172.16.158.131',
      :id => "\x54\x74\xc4\x27\xb7\xa3\x4e\x9b\x51\xb5\x25\xf9\x00\x00\x01\x4a\xdf\xd4\x57\x7e\x80\x01\x01",
      :port => 3057
    }
  end

  describe "#discovery_stream" do

    it "returns a Rex::Java::Serialization::Model::Stream" do
      expect(mod.discovery_stream).to be_a(Rex::Java::Serialization::Model::Stream)
    end

    it "builds a valid stream to discover an jmxrmi endpoing" do
      expect(mod.discovery_stream.encode).to eq(stream_discovery)
    end
  end

  describe "#extract_mbean_server" do
    context "when empty block data" do
      it "returns nil" do
        expect(mod.extract_mbean_server(Rex::Java::Serialization::Model::BlockData.new)). to be_nil
      end
    end

    context "when valid block data" do
      it "returns a hash" do
        expect(mod.extract_mbean_server(Rex::Java::Serialization::Model::BlockData.new(nil, block_data_answer))).to be_a(Hash)
      end

      it "returns a hash containing the end point information" do
        expect(mod.extract_mbean_server(Rex::Java::Serialization::Model::BlockData.new(nil, block_data_answer))).to eq(mbean_server)
      end
    end
  end
end

