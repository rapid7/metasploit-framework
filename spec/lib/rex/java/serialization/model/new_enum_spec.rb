# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::NewEnum do

  subject(:new_enum) do
    described_class.new
  end

  let(:sample_enum) do
    "\x72\x00\x09\x45\x6e\x75\x6d\x73" +
    "\x24\x44\x61\x79\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x12\x00\x00\x78" +
    "\x72\x00\x0e\x6a\x61\x76\x61\x2e" +
    "\x6c\x61\x6e\x67\x2e\x45\x6e\x75" +
    "\x6d\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x12\x00\x00\x78\x70\x74\x00" +
    "\x06\x53\x55\x4e\x44\x41\x59"
  end

  let(:sample_enum_io) { StringIO.new(sample_enum) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::NewEnum" do
      expect(new_enum).to be_a(Rex::Java::Serialization::Model::NewEnum)
    end

    it "initializes enum_description with nil" do
      expect(new_enum.enum_description).to be_nil
    end

    it "initializes constant_name with nil" do
      expect(new_enum.constant_name).to be_nil
    end
  end

  describe "#decode" do
    it "deserializes an Enum" do
      expect(new_enum.decode(sample_enum_io)).to be_a(Rex::Java::Serialization::Model::NewEnum)
    end

    it "deserializes the constant_name correctly" do
      new_enum.decode(sample_enum_io)
      expect(new_enum.constant_name.contents).to eq('SUNDAY')
    end
  end

  describe "#encode" do
    it "serializes an Enum" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'Enums$Day')
      new_class_desc.serial_version = 0
      new_class_desc.flags = 18
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.class_annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.super_class.description.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.Enum')
      new_class_desc.super_class.description.serial_version = 0
      new_class_desc.super_class.description.flags = 18
      new_class_desc.super_class.description.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class.description.class_annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
      new_class_desc.super_class.description.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_enum.enum_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_enum.enum_description.description = new_class_desc
      new_enum.constant_name = Rex::Java::Serialization::Model::Utf.new(nil, 'SUNDAY')

      expect(new_enum.encode.unpack("C*")).to eq(sample_enum.unpack("C*"))
    end
  end

  describe "#to_s" do
    it "prints a sample NewEnum stream" do
      new_enum.decode(sample_enum_io)
      expect(new_enum.to_s).to eq('SUNDAY')
    end
  end
end