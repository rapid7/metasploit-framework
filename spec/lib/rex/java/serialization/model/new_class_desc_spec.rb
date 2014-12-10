# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::NewClassDesc do
  subject(:class_desc_new) do
    described_class.new
  end

  let(:sample) do
    "\x00\x0e\x6a\x61\x76\x61\x2e\x6c\x61\x6e" +
    "\x67\x2e\x42\x79\x74\x65\x9c\x4e\x60\x84\xee\x50\xf5\x1c\x02\x00" +
    "\x01\x42\x00\x05\x76\x61\x6c\x75\x65\x78\x72\x00\x10\x6a\x61\x76" +
    "\x61\x2e\x6c\x61\x6e\x67\x2e\x4e\x75\x6d\x62\x65\x72\x86\xac\x95" +
    "\x1d\x0b\x94\xe0\x8b\x02\x00\x00\x78\x70"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::NewClassDesc" do
      expect(class_desc_new).to be_a(Rex::Java::Serialization::Model::NewClassDesc)
    end

    it "initializes class_name with nil" do
      expect(class_desc_new.class_name).to be_nil
    end

    it "initializes serial_version with 0" do
      expect(class_desc_new.serial_version).to eq(0)
    end

    it "initializes flags with 0" do
      expect(class_desc_new.flags).to eq(0)
    end

    it "initializes fields with empty Array" do
      expect(class_desc_new.fields).to be_empty
    end

    it "initializes class_annotation with nil" do
      expect(class_desc_new.class_annotation).to be_nil
    end

    it "initializes super_class with nil" do
      expect(class_desc_new.super_class).to be_nil
    end
  end

  describe "#decode" do
    it "returns a Rex::Java::Serialization::Model::NewClassDesc" do
      expect(class_desc_new.decode(sample_io)).to be_a(Rex::Java::Serialization::Model::NewClassDesc)
    end

    it "deserializes class_name as Utf" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.class_name).to be_a(Rex::Java::Serialization::Model::Utf)
    end

    it "deserializes class_name contents correctly" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.class_name.contents).to eq('java.lang.Byte')
    end

    it "deserializes serial_version correctly" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.serial_version).to eq(0x9c4e6084ee50f51c)
    end

    it "deserializes flags correctly" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.flags).to eq(2)
    end

    it "deserializes fields" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.fields.length).to eq(1)
    end

    it "deserializes fields contents correctly" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.fields[0].type).to eq('byte')
    end

    it "deserializes class annotation correctly" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.class_annotation).to be_a(Rex::Java::Serialization::Model::Annotation)
    end

    it "deserializes class annotation contents" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.class_annotation.contents[0]).to be_a(Rex::Java::Serialization::Model::EndBlockData)
    end

    it "deserializes super_class" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.super_class).to be_a(Rex::Java::Serialization::Model::ClassDesc)
    end

    it "deserializes super class description" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.super_class.description).to be_a(Rex::Java::Serialization::Model::NewClassDesc)
    end
  end

  describe "#encode" do
    it "serializes a NewClassDesc" do
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

      expect(class_desc_new.encode.unpack("C*")).to eq(sample.unpack("C*"))
    end
  end

  describe "#to_s" do
    it "prints a sample NewClassDesc stream" do
      class_desc_new.decode(sample_io)
      expect(class_desc_new.to_s).to eq('java.lang.Byte, [ value (byte) ], @super_class: java.lang.Number')
    end
  end
end