require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::ClassDescription do
  subject(:class_description) do
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
    it "Rex::Java::Serialization::Model::ClassDescription" do
      expect(class_description).to be_a(Rex::Java::Serialization::Model::ClassDescription)
    end

    it "initializes class_name with nil" do
      expect(class_description.class_name).to be_nil
    end

    it "initializes serial_version with 0" do
      expect(class_description.serial_version).to eq(0)
    end

    it "initializes flags with 0" do
      expect(class_description.flags).to eq(0)
    end

    it "initializes fields with empty Array" do
      expect(class_description.fields).to be_empty
    end

    it "initializes class_annotation with nil" do
      expect(class_description.class_annotation).to be_nil
    end

    it "initializes super_class with nil" do
      expect(class_description.super_class).to be_nil
    end
  end

  describe "#decode" do
    it "returns a Rex::Java::Serialization::Model::ClassDescription" do
      expect(class_description.decode(sample_io)).to be_a(Rex::Java::Serialization::Model::ClassDescription)
    end

    it "unserializes class_name as Utf" do
      class_description.decode(sample_io)
      expect(class_description.class_name).to be_a(Rex::Java::Serialization::Model::Utf)
    end

    it "unserializes class_name contents correctly" do
      class_description.decode(sample_io)
      expect(class_description.class_name.contents).to eq('java.lang.Byte')
    end

    it "unserializes serial_version correctly" do
      class_description.decode(sample_io)
      expect(class_description.serial_version).to eq(0x9c4e6084ee50f51c)
    end

    it "unserializes flags correctly" do
      class_description.decode(sample_io)
      expect(class_description.flags).to eq(2)
    end

    it "unserializes fields" do
      class_description.decode(sample_io)
      expect(class_description.fields.length).to eq(1)
    end

    it "unserializes fields contents correctly" do
      class_description.decode(sample_io)
      expect(class_description.fields[0].type).to eq('byte')
    end

    it "unserializes class annotation correctly" do
      class_description.decode(sample_io)
      expect(class_description.class_annotation).to be_a(Rex::Java::Serialization::Model::Annotation)
    end

    it "unserializes class annotation contents" do
      class_description.decode(sample_io)
      expect(class_description.class_annotation.contents).to be_empty
    end

    it "unserializes super_class" do
      class_description.decode(sample_io)
      expect(class_description.super_class).to be_a(Rex::Java::Serialization::Model::ClassDescription)
    end
  end

  describe "#encode" do
    it do
      class_description.class_name = Rex::Java::Serialization::Model::Utf.new('java.lang.Byte')
      class_description.serial_version = 0x9c4e6084ee50f51c
      class_description.flags = 2
      field = Rex::Java::Serialization::Model::Field.new
      field.type = 'byte'
      field.name = Rex::Java::Serialization::Model::Utf.new('value')
      class_description.fields << field
      class_description.class_annotation = Rex::Java::Serialization::Model::Annotation.new

      super_class = Rex::Java::Serialization::Model::ClassDescription.new
      super_class.class_name = Rex::Java::Serialization::Model::Utf.new('java.lang.Number')
      super_class.serial_version = 0x86ac951d0b94e08b
      super_class.flags = 2
      super_class.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      super_class.super_class = nil

      class_description.super_class = super_class

      expect(class_description.encode.unpack("C*")).to eq(sample.unpack("C*"))
    end
  end
end