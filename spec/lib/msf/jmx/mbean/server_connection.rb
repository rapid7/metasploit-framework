# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'msf/jmx'

describe Msf::Jmx::MBean::ServerConnection do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Jmx
    mod.send(:initialize)
    mod
  end

  let(:mbean_name) { 'MBeanSample' }

  describe "#create_mbean_stream" do
    it "returns a Rex::Java::Serialization::Model::Stream" do
      expect(mod.create_mbean_stream).to be_a(Rex::Java::Serialization::Model::Stream)
    end

    context "when no opts" do
      it "builds a default stream" do
        expect(mod.create_mbean_stream.contents[1].contents).to eq('')
      end
    end

    context "when opts" do
      it "builds a stream having opts into account" do
        expect(mod.create_mbean_stream(name: 'MBeanSample').contents[1].contents).to eq('MBeanSample')
      end
    end
  end
end

