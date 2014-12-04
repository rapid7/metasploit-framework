require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::Stream do

  subject(:stream) do
    described_class.new
  end

  let(:easy_object_stream) do
    "\xac\xed\x00\x05\x73\x72\x00\x04" +
    "\x45\x61\x73\x79\x74\x1d\xe1\xbc" +
    "\xbb\x2f\xcb\xaa\x02\x00\x01\x49" +
    "\x00\x03\x53\x53\x4e\x78\x70\x41" +
    "\x42\x43\x44"
  end
  let(:easy_object_stream_io) { StringIO.new(easy_object_stream) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::Stream" do
      expect(stream).to be_a(Rex::Java::Serialization::Model::Stream)
    end

    it "initializes magic with java serialized stream signature" do
      expect(stream.magic).to eq(Rex::Java::Serialization::STREAM_MAGIC)
    end

    it "initializes version with java serialized stream default version " do
      expect(stream.version).to eq(Rex::Java::Serialization::STREAM_VERSION)
    end
  end

  describe "#decode" do
    context "when deserializing a simple Object stream" do
      it "deserializes an Stream" do
        expect(stream.decode(easy_object_stream_io)).to be_a(Rex::Java::Serialization::Model::Stream)
      end

      it "deserializes the signature correctly" do
        stream.decode(easy_object_stream_io)
        expect(stream.magic).to eq(Rex::Java::Serialization::STREAM_MAGIC)
      end

      it "deserializes all the contents" do
        stream.decode(easy_object_stream_io)
        expect(stream.contents.length).to eq(1)
      end

      it "deserializes a simple object correctly" do
        stream.decode(easy_object_stream_io)
        expect(stream.contents[0]).to be_an(Rex::Java::Serialization::Model::NewObject)
      end
    end
  end

  describe "#encode" do
    context "when serializing a simple Object stream" do
      it "serializes the Stream" do
        new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
        new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('Easy')
        new_class_desc.serial_version = 0x741de1bcbb2fcbaa
        new_class_desc.flags = 2
        field = Rex::Java::Serialization::Model::Field.new
        field.type = 'int'
        field.name = Rex::Java::Serialization::Model::Utf.new('SSN')
        new_class_desc.fields << field
        new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
        new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
        new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

        new_object = Rex::Java::Serialization::Model::NewObject.new
        new_object.class_desc = Rex::Java::Serialization::Model::ClassDesc.new
        new_object.class_desc.description = new_class_desc
        new_object.class_data = [['int', 0x41424344]]

        stream.contents << new_object
        expect(stream.encode.unpack("C*")).to eq(easy_object_stream.unpack("C*"))
      end
    end
  end

end