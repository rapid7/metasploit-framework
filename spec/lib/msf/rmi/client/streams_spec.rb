# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java/serialization'
require 'rex/proto/rmi'
require 'msf/rmi/client'

describe Msf::Rmi::Client::Streams do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Rmi::Client
    mod.send(:initialize)
    mod
  end

  let(:default_header) { "JRMI\x00\x02\x4b" }
  let(:header_opts) do
    {
      :version  => 1,
      :protocol => Rex::Proto::Rmi::Model::MULTIPLEX_PROTOCOL
    }
  end
  let(:opts_header) { "JRMI\x00\x01\x4d" }

  let(:default_call) { "\x50\xac\xed\x00\x05" }
  let(:call_opts) do
    {
      :message_id => Rex::Proto::Rmi::Model::PING_MESSAGE
    }
  end
  let(:opts_call) { "\x52\xac\xed\x00\x05" }

  let(:file_jar) { 'file:RMIClassLoaderSecurityTest/test.jar' }

  let(:call_gc) do
    "\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\xf6\xb6\x89\x8d\x8b\xf2\x86\x43\x75\x72\x00\x18\x5b\x4c\x6a\x61" +
    "\x76\x61\x2e\x72\x6d\x69\x2e\x73\x65\x72\x76\x65\x72\x2e\x4f\x62" +
    "\x6a\x49\x44\x3b\x87\x13\x00\xb8\xd0\x2c\x64\x7e\x02\x00\x00\x70" +
    "\x78\x70\x00\x00\x00\x00\x77\x08\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x73\x72\x00\x14\x6d\x65\x74\x61\x73\x70\x6c\x6f\x69\x74\x2e\x52" +
    "\x4d\x49\x4c\x6f\x61\x64\x65\x72\xa1\x65\x44\xba\x26\xf9\xc2\xf4" +
    "\x02\x00\x00\x74\x00\x28\x66\x69\x6c\x65\x3a\x52\x4d\x49\x43\x6c" +
    "\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x53\x65\x63\x75\x72\x69\x74" +
    "\x79\x54\x65\x73\x74\x2f\x74\x65\x73\x74\x2e\x6a\x61\x72\x78\x70" +
    "\x77\x01\x00"
  end

  describe "#build_header" do
    context "when no opts" do
      it "creates a Rex::Proto::Rmi::Model::OutputHeader" do
        expect(mod.build_header).to be_a(Rex::Proto::Rmi::Model::OutputHeader)
      end

      it "creates a default OutputHeader" do
        expect(mod.build_header.encode).to eq(default_header)
      end
    end

    context "when opts" do
      it "creates a Rex::Proto::Rmi::Model::OutputHeader" do
        expect(mod.build_header(header_opts)).to be_a(Rex::Proto::Rmi::Model::OutputHeader)
      end

      it "creates a OutputHeader with data from opts" do
        expect(mod.build_header(header_opts).encode).to eq(opts_header)
      end
    end
  end

  describe "#build_call" do
    context "when no opts" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_call).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a default Call" do
        expect(mod.build_call.encode).to eq(default_call)
      end
    end

    context "when opts" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_call(call_opts)).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a OutputHeader with data from opts" do
        expect(mod.build_call(call_opts).encode).to eq(opts_call)
      end
    end
  end

  describe "#build_call" do
    context "when using test file: jar" do
      it "creates a correct stream" do
        expect(mod.build_gc_call_data(file_jar).encode).to eq(call_gc)
      end
    end
  end
end

