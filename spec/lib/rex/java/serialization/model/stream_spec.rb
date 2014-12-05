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

  let(:char_array_stream) do
    "\xac\xed\x00\x05\x75\x72\x00\x02" +
    "\x5b\x43\xb0\x26\x66\xb0\xe2\x5d" +
    "\x84\xac\x02\x00\x00\x78\x70\x00" +
    "\x00\x00\x02\x00\x61\x00\x62"
  end
  let(:char_array_stream_io) { StringIO.new(char_array_stream) }

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

    context "when deserializing a char array" do
      it "deserializes an Stream" do
        expect(stream.decode(char_array_stream_io)).to be_a(Rex::Java::Serialization::Model::Stream)
      end

      it "deserializes the char array correctly" do
        stream.decode(char_array_stream_io)
        expect(stream.contents[0]).to be_an(Rex::Java::Serialization::Model::NewArray)
      end
    end
  end

  describe "#encode" do
    context "when serializing a simple Object stream" do
      it "serializes the Stream" do
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

        new_object = Rex::Java::Serialization::Model::NewObject.new
        new_object.class_desc = Rex::Java::Serialization::Model::ClassDesc.new
        new_object.class_desc.description = new_class_desc
        new_object.class_data = [['int', 0x41424344]]

        stream.contents << new_object
        expect(stream.encode.unpack("C*")).to eq(easy_object_stream.unpack("C*"))
      end
    end

    context "when serializing a char array" do
      it "serializes the Stream" do
        new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
        new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, '[C')
        new_class_desc.serial_version = 0xb02666b0e25d84ac
        new_class_desc.flags = 2
        new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
        new_class_desc.class_annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
        new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
        new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

        new_array = Rex::Java::Serialization::Model::NewArray.new
        new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
        new_array.array_description.description = new_class_desc
        new_array.type = 'char'
        new_array.values = [97, 98]

        stream.contents << new_array
        expect(stream.encode.unpack("C*")).to eq(char_array_stream.unpack("C*"))
      end
    end
  end

end