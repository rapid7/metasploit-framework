# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'stringio'

RSpec.describe Rex::Java::Serialization::Model::NewObject do

  subject(:new_object) do
    described_class.new
  end

  let(:easy_object) do
    "\x72\x00\x04\x45\x61\x73\x79\x74" +
    "\x1d\xe1\xbc\xbb\x2f\xcb\xaa\x02" +
    "\x00\x01\x49\x00\x03\x53\x53\x4e" +
    "\x78\x70\x41\x42\x43\x44"
  end

  let(:easy_object_io) { StringIO.new(easy_object) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::NewObject" do
      expect(new_object).to be_a(Rex::Java::Serialization::Model::NewObject)
    end

    it "initializes class_desc with nil" do
      expect(new_object.class_desc).to be_nil
    end

    it "initializes class_data with empty array" do
      expect(new_object.class_data).to be_empty
    end
  end

  describe "#decode" do
    it "deserializes an object" do
      expect(new_object.decode(easy_object_io)).to be_a(Rex::Java::Serialization::Model::NewObject)
    end

    it "deserializes the object class fields correctly" do
      new_object.decode(easy_object_io)
      expect(new_object.class_desc.description.fields.length).to eq(1)
    end

    it "deserializes the object class data correctly" do
      new_object.decode(easy_object_io)
      expect(new_object.class_data).to eq([['int', 0x41424344]])
    end
  end


  describe "#encode" do
    it "serializes an Object" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'Easy')
      new_class_desc.serial_version = 0x741de1bcbb2fcbaa
      new_class_desc.flags = 2
      field = Rex::Java::Serialization::Model::Field.new
      field.type = 'int'
      field.name = Rex::Java::Serialization::Model::Utf.new(nil, 'SSN')
      new_class_desc.fields << field
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.class_annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_object.class_desc = Rex::Java::Serialization::Model::ClassDesc.new
      new_object.class_desc.description = new_class_desc
      new_object.class_data = [['int', 0x41424344]]

      expect(new_object.encode.unpack("C*")).to eq(easy_object.unpack("C*"))
    end
  end

  describe "#to_s" do
    it "prints a sample Object stream" do
      new_object.decode(easy_object_io)
      expect(new_object.to_s).to eq('Easy => { ["int", 1094861636] }')
    end
  end
end