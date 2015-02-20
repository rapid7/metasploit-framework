# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'msf/java/jmx'

describe Msf::Java::Jmx::Discovery do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Java::Jmx
    mod.send(:initialize)
    mod
  end

  let(:stream_discovery) do
    "\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" +
    "\x44\x15\x4d\xc9\xd4\xe6\x3b\xdf\x74\x00\x06\x6a\x6d\x78\x72\x6d" +
    "\x69"
  end

  describe "#discovery_stream" do

    it "returns a Rex::Java::Serialization::Model::Stream" do
      expect(mod.discovery_stream).to be_a(Rex::Java::Serialization::Model::Stream)
    end

    it "builds a valid stream to discover an jmxrmi endpoing" do
      expect(mod.discovery_stream.encode).to eq(stream_discovery)
    end
  end
end

