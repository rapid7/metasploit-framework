# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/java'
require 'msf/java/jmx'

describe Msf::Java::Jmx::Handshake do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Java::Jmx
    mod.send(:initialize)
    mod
  end

  let(:handshake_stream) do
    "\xac\xed\x00\x05\x77\x0d\x30\xff\xff\xff\xff\xf0\xe0\x74\xea\xad" +
    "\x0c\xae\xa8\x70"
  end

  let(:auth_stream) do
    "\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53" +
    "\x74\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00" +
    "\x00\x70\x78\x70\x00\x00\x00\x02\x74\x00\x04\x72\x6f\x6c\x65\x74" +
    "\x00\x08\x70\x61\x73\x73\x77\x6f\x72\x64"
  end

  describe "#handshake_stream" do
    it "returns a Rex::Java::Serialization::Model::Stream" do
      expect(mod.handshake_stream(0)).to be_a(Rex::Java::Serialization::Model::Stream)
    end

    it "builds a correct stream" do
      expect(mod.handshake_stream(0).encode).to eq(handshake_stream)
    end
  end

  describe "#auth_array_stream" do
    it "returns a Rex::Java::Serialization::Model::Stream" do
      expect(mod.auth_array_stream('role', 'password')).to be_a(Rex::Java::Serialization::Model::NewArray)
    end

    it "builds a correct stream" do
      expect(mod.auth_array_stream('role', 'password').encode).to eq(auth_stream)
    end
  end
end

