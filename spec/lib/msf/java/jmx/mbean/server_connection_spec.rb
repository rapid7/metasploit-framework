# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'msf/java/jmx'

describe Msf::Java::Jmx::Mbean::ServerConnection do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Java::Jmx
    mod.send(:initialize)
    mod
  end

  let(:mbean_sample) { 'MBeanSample' }
  let(:sample_args) do
    {'arg1' => 'java.lang.String'}
  end

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
        expect(mod.create_mbean_stream(name: mbean_sample).contents[1].contents).to eq(mbean_sample)
      end
    end
  end

  describe "#get_object_instance_stream" do
    it "returns a Rex::Java::Serialization::Model::Stream" do
      expect(mod.get_object_instance_stream).to be_a(Rex::Java::Serialization::Model::Stream)
    end

    context "when no opts" do
      it "builds a default stream" do
        expect(mod.get_object_instance_stream.contents[2].contents).to eq('')
      end
    end

    context "when opts" do
      it "builds a stream having opts into account" do
        expect(mod.get_object_instance_stream(name: mbean_sample).contents[2].contents).to eq(mbean_sample)
      end
    end
  end

  describe "#invoke_stream" do
    it "returns a Rex::Java::Serialization::Model::Stream" do
      expect(mod.invoke_stream).to be_a(Rex::Java::Serialization::Model::Stream)
    end

    context "when no opts" do
      it "builds a default stream" do
        expect(mod.invoke_stream.contents[2].contents).to eq('')
      end
    end

    context "when opts" do
      it "builds a stream having opts into account" do
        expect(mod.invoke_stream(object: mbean_sample).contents[2].contents).to eq(mbean_sample)
      end
    end
  end

  describe "#invoke_arguments_stream" do
    it "returns a Rex::Java::Serialization::Model::Stream" do
      expect(mod.invoke_arguments_stream).to be_a(Rex::Java::Serialization::Model::Stream)
    end

    context "when no opts" do
      it "builds a default stream" do
        expect(mod.invoke_arguments_stream.contents[0].values.length).to eq(0)
      end
    end

    context "when opts" do
      it "builds a stream having opts into account" do
        expect(mod.invoke_arguments_stream(sample_args).contents[0].values[0].contents).to eq(sample_args['arg1'])
      end
    end
  end

end

