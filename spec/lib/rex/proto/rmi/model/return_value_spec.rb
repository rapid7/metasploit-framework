# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'
require 'rex/java'

RSpec.describe Rex::Proto::Rmi::Model::ReturnValue do

  subject(:return_value) do
    described_class.new
  end

  let(:return_value_stream) do
    "\xac\xed\x00\x05\x77\x0f\x01\xd2\x4f\xdf\x47\x00\x00\x01\x49" +
    "\xb5\xe4\x92\x78\x80\x15\x73\x72\x00\x12\x6a\x61\x76\x61\x2e\x72" +
    "\x6d\x69\x2e\x64\x67\x63\x2e\x4c\x65\x61\x73\x65\xb0\xb5\xe2\x66" +
    "\x0c\x4a\xdc\x34\x02\x00\x02\x4a\x00\x05\x76\x61\x6c\x75\x65\x4c" +
    "\x00\x04\x76\x6d\x69\x64\x74\x00\x13\x4c\x6a\x61\x76\x61\x2f\x72" +
    "\x6d\x69\x2f\x64\x67\x63\x2f\x56\x4d\x49\x44\x3b\x70\x78\x70\x00" +
    "\x00\x00\x00\x00\x09\x27\xc0\x73\x72\x00\x11\x6a\x61\x76\x61\x2e" +
    "\x72\x6d\x69\x2e\x64\x67\x63\x2e\x56\x4d\x49\x44\xf8\x86\x5b\xaf" +
    "\xa4\xa5\x6d\xb6\x02\x00\x02\x5b\x00\x04\x61\x64\x64\x72\x74\x00" +
    "\x02\x5b\x42\x4c\x00\x03\x75\x69\x64\x74\x00\x15\x4c\x6a\x61\x76" +
    "\x61\x2f\x72\x6d\x69\x2f\x73\x65\x72\x76\x65\x72\x2f\x55\x49\x44" +
    "\x3b\x70\x78\x70\x75\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8\x06\x08" +
    "\x54\xe0\x02\x00\x00\x70\x78\x70\x00\x00\x00\x08\x6b\x02\xc7\x72" +
    "\x60\x1c\xc7\x95\x73\x72\x00\x13\x6a\x61\x76\x61\x2e\x72\x6d\x69" +
    "\x2e\x73\x65\x72\x76\x65\x72\x2e\x55\x49\x44\x0f\x12\x70\x0d\xbf" +
    "\x36\x4f\x12\x02\x00\x03\x53\x00\x05\x63\x6f\x75\x6e\x74\x4a\x00" +
    "\x04\x74\x69\x6d\x65\x49\x00\x06\x75\x6e\x69\x71\x75\x65\x70\x78" +
    "\x70\x80\x01\x00\x00\x01\x49\xb5\xf8\x00\xea\xe9\x62\xc1\xc0"
  end

  let(:return_value_stream_io) { StringIO.new(return_value_stream) }

  describe "#decode" do
    it "returns the Rex::Proto::Rmi::Model::ReturnValue decoded" do
      expect(return_value.decode(return_value_stream_io)).to eq(return_value)
    end

    it "decodes code correctly" do
      return_value.decode(return_value_stream_io)
      expect(return_value.code).to eq(Rex::Proto::Rmi::Model::RETURN_VALUE)
    end

    it "decodes the uid correctly" do
      return_value.decode(return_value_stream_io)
      expect(return_value.uid).to be_a(Rex::Proto::Rmi::Model::UniqueIdentifier)
    end

    it "decodes the value correctly" do
      return_value.decode(return_value_stream_io)
      expect(return_value.value).to be_an(Array)
    end

    it "decodes the value as an object" do
      return_value.decode(return_value_stream_io)
      expect(return_value.value[0]).to be_an(Rex::Java::Serialization::Model::NewObject)
    end

    it "decodes the type of object in the value correctly" do
      return_value.decode(return_value_stream_io)
      expect(return_value.value[0].class_desc.description.class_name.contents).to eq('java.rmi.dgc.Lease')
    end
  end

  describe "#encode" do
    it "re-encodes a ReturnData stream correctly" do
      return_value.decode(return_value_stream_io)
      expect(return_value.encode).to eq(return_value_stream)
    end
  end

  describe "#is_exception?" do
    it "return false unless the return value is an exception" do
      return_value.decode(return_value_stream_io)
      expect(return_value.is_exception?).to be_falsey
    end
  end

  describe "#get_class_name" do
    it "returns the class name of the object in the return value" do
      return_value.decode(return_value_stream_io)
      expect(return_value.get_class_name).to eq('java.rmi.dgc.Lease')
    end
  end
end
