# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java/serialization'
require 'msf/java/rmi/util'

describe Msf::Java::Rmi::Util do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Java::Rmi::Util
    mod.send(:initialize)
    mod
  end

  let(:interface_methods) do
    [
      {name: 'sayHello', descriptor: '()Ljava/lang/String;'},
      {name: 'sayHelloTwo', descriptor: '(Ljava/lang/String;)Ljava/lang/String;'}
    ]
  end

  let(:interface_exceptions) do
    ['java.rmi.RemoteException']
  end

  let(:interface_hash) do
    0x3e664fcbd9e953bb
  end

  let(:method_signature) do
    'sayHello()Ljava/lang/String;'
  end

  let(:method_hash) do
    0x53e0822d3e3724df
  end

  let(:dgc_methods) do
    [
      {name: 'clean', descriptor: '([Ljava/rmi/server/ObjID;JLjava/rmi/dgc/VMID;Z)V'},
      {name: 'dirty', descriptor: '([Ljava/rmi/server/ObjID;JLjava/rmi/dgc/Lease;)Ljava/rmi/dgc/Lease;'}
    ]
  end

  let(:dgc_exceptions) do
    ['java.rmi.RemoteException']
  end

  let(:dgc_hash) do
    0xf6b6898d8bf28643
  end

  describe "#calculate_interface_hash" do
    context "when an example interface is provided" do
      it "generates a correct interface hash" do
        expect(mod.calculate_interface_hash(interface_methods, interface_exceptions)).to eq(interface_hash)
      end
    end

    context "when a DGC interface is provided" do
      it "generates a correct interface hash" do
        expect(mod.calculate_interface_hash(dgc_methods, dgc_exceptions)).to eq(dgc_hash)
      end
    end
  end

  describe "#calculate_method_hash" do
    it "generates a correct interface hash" do
      expect(mod.calculate_method_hash(method_signature)).to eq(method_hash)
    end
  end
end

