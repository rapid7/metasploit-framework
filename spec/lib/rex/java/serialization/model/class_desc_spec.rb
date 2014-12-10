# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::ClassDesc do
  subject(:class_desc) do
    described_class.new
  end

  let(:sample) do
    "\x72\x00\x0e\x6a\x61\x76\x61\x2e\x6c\x61\x6e" +
    "\x67\x2e\x42\x79\x74\x65\x9c\x4e\x60\x84\xee\x50\xf5\x1c\x02\x00" +
    "\x01\x42\x00\x05\x76\x61\x6c\x75\x65\x78\x72\x00\x10\x6a\x61\x76" +
    "\x61\x2e\x6c\x61\x6e\x67\x2e\x4e\x75\x6d\x62\x65\x72\x86\xac\x95" +
    "\x1d\x0b\x94\xe0\x8b\x02\x00\x00\x78\x70"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::NewClassDesc" do
      expect(class_desc).to be_a(Rex::Java::Serialization::Model::ClassDesc)
    end

    it "initializes description with nil" do
      expect(class_desc.description).to be_nil
    end
  end

  describe "#decode" do
    it "returns a Rex::Java::Serialization::Model::ClassDesc" do
      expect(class_desc.decode(sample_io)).to be_a(Rex::Java::Serialization::Model::ClassDesc)
    end

    it "deserializes the description correctly" do
      class_desc.decode(sample_io)
      expect(class_desc.description).to be_a(Rex::Java::Serialization::Model::NewClassDesc)
    end
  end

  describe "#encode" do
    it "serializes a ClassDesc" do
      super_class_desc_new = Rex::Java::Serialization::Model::NewClassDesc.new
      super_class_desc_new.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.Number')
      super_class_desc_new.serial_version = 0x86ac951d0b94e08b
      super_class_desc_new.flags = 2
      super_class_desc_new.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      super_class_desc_new.class_annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
      super_class_desc_new.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      super_class_desc_new.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      super_class_desc = Rex::Java::Serialization::Model::ClassDesc.new
      super_class_desc.description = super_class_desc_new

      class_desc_new = Rex::Java::Serialization::Model::NewClassDesc.new
      class_desc_new.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.Byte')
      class_desc_new.serial_version = 0x9c4e6084ee50f51c
      class_desc_new.flags = 2
      field = Rex::Java::Serialization::Model::Field.new
      field.type = 'byte'
      field.name = Rex::Java::Serialization::Model::Utf.new(nil, 'value')
      class_desc_new.fields << field
      class_desc_new.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      class_desc_new.class_annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
      class_desc_new.super_class = super_class_desc

      class_desc.description = class_desc_new

      expect(class_desc.encode.unpack("C*")).to eq(sample.unpack("C*"))
    end
  end

  describe "#to_s" do
    it "prints a sample ClassDesc" do
      class_desc.decode(sample_io)
      expect(class_desc.to_s).to be_a(String)
    end
  end
end