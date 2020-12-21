# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java/serialization'
require 'rex/proto/rmi'
require 'msf/core/exploit/java/rmi/client'

RSpec.describe ::Msf::Exploit::Remote::Java::Rmi::Client::Registry::Builder do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Exploit::Remote::Java::Rmi::Client
    mod.send(:initialize)
    mod
  end

  let(:default_lookup) do
    "\x50\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x02\x44\x15\x4d\xc9\xd4\xe6\x3b\xdf\x74\x00\x00"
  end
  let(:lookup_opts) do
    {
      name: 'test'
    }
  end
  let(:name_lookup) do
    "\x50\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x02\x44\x15\x4d\xc9\xd4\xe6\x3b\xdf\x74\x00\x04\x74\x65\x73\x74"
  end

  let(:default_list_call) do
    "\x50\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x01\x44\x15\x4d\xc9\xd4\xe6\x3b\xdf"
  end

  describe "#build_registry_lookup" do
    context "when no opts" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_registry_lookup).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a lookup Call for an empty name" do
        expect(mod.build_registry_lookup.encode).to eq(default_lookup)
      end
    end

    context "when opts with name" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_registry_lookup(lookup_opts)).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a lookup Call for the provided name" do
        expect(mod.build_registry_lookup(lookup_opts).encode).to eq(name_lookup)
      end
    end
  end

  describe "#build_registry_list" do
    context "when no opts" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_registry_list).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a default Call" do
        expect(mod.build_registry_list.encode).to eq(default_list_call)
      end
    end
  end
end

