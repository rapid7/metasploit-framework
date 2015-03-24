# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/java/serialization'
require 'rex/proto/rmi'
require 'msf/java/rmi/client'

describe Msf::Java::Rmi::Client::Jmx::Connection::Builder do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Java::Rmi::Client
    mod.send(:initialize)
    mod
  end

  let(:default_get_object_instance) do
    "\x50\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff" +
    "\xff\xf0\xe0\x74\xea\xad\x0c\xae\xa8\x70"
  end

  let(:mlet_name) do
    'DefaultDomain:type=MLet'
  end

  let(:mlet_get_object_instance) do
    "\x50\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff" +
    "\xff\xf0\xe0\x74\xea\xad\x0c\xae\xa8\x70"
  end

  describe "#build_jmx_get_object_instance" do
    context "when no opts" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_jmx_new_client).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a getObjectInstance call for an empty object name" do
        expect(mod.build_jmx_new_client.encode).to eq(default_get_object_instance)
      end
    end

    context "when opts with class name" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_jmx_new_client(name: mlet_name)).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a newClient Call with credentials" do
        expect(mod.build_jmx_new_client(name: mlet_name).encode).to eq(mlet_get_object_instance)
      end
    end
  end

  describe "#build_jmx_new_client_args" do
    it "return an Array" do
      expect(mod.build_jmx_get_object_instance_args(mlet_name)).to be_an(Array)
    end

    it "returns an Array with 4 elements" do
      expect(mod.build_jmx_get_object_instance_args(mlet_name).length).to eq(4)
    end

    it "returns an Array whose second element is an utf string with the object name" do
      expect(mod.build_jmx_get_object_instance_args(mlet_name)[1].contents).to eq(mlet_name)
    end
  end
end

