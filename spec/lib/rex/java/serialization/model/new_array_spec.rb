require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::NewArray do
  subject(:new_array) do
    described_class.new
  end

  let(:boolean_array) do
    "\x72\x00\x02\x5b\x5a\x57\x8f\x20" +
    "\x39\x14\xb8\x5d\xe2\x02\x00\x00" +
    "\x78\x70\x00\x00\x00\x0a\x01\x00" +
    "\x01\x01\x01\x01\x01\x01\x01\x00"
  end
  let(:boolean_array_io) { StringIO.new(boolean_array) }

  let(:byte_array) do
    "\x72\x00\x02\x5b\x42\xac\xf3\x17" +
    "\xf8\x06\x08\x54\xe0\x02\x00\x00" +
    "\x78\x70\x00\x00\x00\x02\xec\x41"
  end
  let(:byte_array_io) { StringIO.new(byte_array) }

  let(:char_array) do
    "\x72\x00\x02\x5b\x43\xb0\x26\x66" +
    "\xb0\xe2\x5d\x84\xac\x02\x00\x00" +
    "\x78\x70\x00\x00\x00\x02\x00\x61" +
    "\x00\x62"
  end
  let(:char_array_io) { StringIO.new(char_array) }

  let(:short_array) do
    "\x72\x00\x02\x5b\x53\xef\x83\x2e" +
    "\x06\xe5\x5d\xb0\xfa\x02\x00\x00" +
    "\x78\x70\x00\x00\x00\x02\xff\xec" +
    "\x00\x41"
  end
  let(:short_array_io) { StringIO.new(short_array) }

  let(:double_array) do
    "\x72\x00\x02\x5b\x44\x3e\xa6\x8c" +
    "\x14\xab\x63\x5a\x1e\x02\x00\x00" +
    "\x78\x70\x00\x00\x00\x02\x3f\xd0" +
    "\x00\x00\x00\x00\x00\x00\x3f\xca" +
    "\xe1\x47\xae\x14\x7a\xe1"
  end
  let(:double_array_io) { StringIO.new(double_array) }

  let(:float_array) do
    "\x72\x00\x02\x5b\x46\x0b\x9c\x81" +
    "\x89\x22\xe0\x0c\x42\x02\x00\x00" +
    "\x78\x70\x00\x00\x00\x02\x3f\x80" +
    "\x00\x00\x40\x00\x00\x00"
  end
  let(:float_array_io) { StringIO.new(float_array) }

  let(:int_array) do
    "\x72\x00\x02\x5b\x49\x4d\xba\x60" +
    "\x26\x76\xea\xb2\xa5\x02\x00\x00" +
    "\x78\x70\x00\x00\x00\x02\xff\xff" +
    "\xff\xec\x00\x00\x00\x41"
  end
  let(:int_array_io) { StringIO.new(int_array) }

  let(:long_array) do
    "\x72\x00\x02\x5b\x4a\x78\x20\x04" +
    "\xb5\x12\xb1\x75\x93\x02\x00\x00" +
    "\x78\x70\x00\x00\x00\x02\xff\xff" +
    "\xff\xff\xff\xff\xff\xec\x00\x00" +
    "\x00\x00\x00\x00\x00\x41"
  end
  let(:long_array_io) { StringIO.new(long_array) }

  let(:string_array) do
    "\x72\x00\x13\x5b\x4c\x6a\x61\x76" +
    "\x61\x2e\x6c\x61\x6e\x67\x2e\x53" +
    "\x74\x72\x69\x6e\x67\x3b\xad\xd2" +
    "\x56\xe7\xe9\x1d\x7b\x47\x02\x00" +
    "\x00\x78\x70\x00\x00\x00\x01\x74" +
    "\x00\x03\x6d\x73\x66"
  end
  let(:string_array_io) { StringIO.new(string_array) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::NewArray" do
      expect(new_array).to be_a(Rex::Java::Serialization::Model::NewArray)
    end

    it "initializes array_description with nil" do
      expect(new_array.array_description).to be_nil
    end

    it "initializes type with an empty String" do
      expect(new_array.type).to be_empty
    end

    it "initializes values with an empty Array" do
      expect(new_array.values).to be_empty
    end
  end

  describe "#decode" do

    context "when boolean Array" do
      it "unserializes Array" do
        expect(new_array.decode(boolean_array_io)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "unserializes type correctly" do
        new_array.decode(boolean_array_io)
        expect(new_array.type).to eq('boolean')
      end

      it "unserializes values correctly" do
        new_array.decode(boolean_array_io)
        expect(new_array.values).to eq([1, 0, 1, 1, 1, 1, 1, 1, 1, 0])
      end
    end

    context "when byte Array" do
      it "unserializes Array" do
        expect(new_array.decode(byte_array_io)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "unserializes type correctly" do
        new_array.decode(byte_array_io)
        expect(new_array.type).to eq('byte')
      end

      it "unserializes values correctly" do
        new_array.decode(byte_array_io)
        expect(new_array.values).to eq([-20, 65])
      end
    end

    context "when char Array" do
      it "unserializes Array" do
        expect(new_array.decode(char_array_io)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "unserializes type correctly" do
        new_array.decode(char_array_io)
        expect(new_array.type).to eq('char')
      end

      it "unserializes values correctly" do
        new_array.decode(char_array_io)
        expect(new_array.values).to eq([97, 98])
      end
    end

    context "when short Array" do
      it "unserializes Array" do
        expect(new_array.decode(short_array_io)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "unserializes type correctly" do
        new_array.decode(short_array_io)
        expect(new_array.type).to eq('short')
      end

      it "unserializes values correctly" do
        new_array.decode(short_array_io)
        expect(new_array.values).to eq([-20, 65])
      end
    end

    context "when double Array" do
      it "unserializes Array" do
        expect(new_array.decode(double_array_io)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "unserializes type correctly" do
        new_array.decode(double_array_io)
        expect(new_array.type).to eq('double')
      end

      it "unserializes values correctly" do
        new_array.decode(double_array_io)
        expect(new_array.values).to eq([0.25, 0.21])
      end
    end

    context "when float Array" do
      it "decodes a float Array" do
        expect(new_array.decode(float_array_io)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "unserializes type correctly" do
        new_array.decode(float_array_io)
        expect(new_array.type).to eq('float')
      end

      it "unserializes values correctly" do
        new_array.decode(float_array_io)
        expect(new_array.values).to eq([1.0, 2.0])
      end
    end

    context "when int Array" do
      it "unserializes Array" do
        expect(new_array.decode(int_array_io)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "unserializes type correctly" do
        new_array.decode(int_array_io)
        expect(new_array.type).to eq('int')
      end

      it "unserializes values correctly" do
        new_array.decode(int_array_io)
        expect(new_array.values).to eq([-20, 65])
      end
    end

    context "when long Array" do
      it "unserializes Array" do
        expect(new_array.decode(long_array_io)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "unserializes type correctly" do
        new_array.decode(long_array_io)
        expect(new_array.type).to eq('long')
      end

      it "unserializes values correctly" do
        new_array.decode(long_array_io)
        expect(new_array.values).to eq([-20, 65])
      end
    end

    context "when unsupported Array type" do
      it "raises a RuntimeError" do
        expect { new_array.decode(string_array_io) }.to raise_error(RuntimeError)
      end
    end

  end

  describe "#encode" do
    it "encodes a boolean Array" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('[Z')
      new_class_desc.serial_version = 0x578f203914b85de2
      new_class_desc.flags = 2
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_array.array_description.description = new_class_desc
      new_array.type = 'boolean'
      new_array.values = [1, 0, 1, 1, 1, 1, 1, 1, 1, 0]

      expect(new_array.encode.unpack("C*")).to eq(boolean_array.unpack("C*"))
    end

    it "encodes a byte Array" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('[B')
      new_class_desc.serial_version = 0xacf317f8060854e0
      new_class_desc.flags = 2
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_array.array_description.description = new_class_desc
      new_array.type = 'byte'
      new_array.values = [-20, 65]

      expect(new_array.encode.unpack("C*")).to eq(byte_array.unpack("C*"))
    end

    it "encodes a char Array" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('[C')
      new_class_desc.serial_version = 0xb02666b0e25d84ac
      new_class_desc.flags = 2
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_array.array_description.description = new_class_desc
      new_array.type = 'char'
      new_array.values = [97, 98]

      expect(new_array.encode.unpack("C*")).to eq(char_array.unpack("C*"))
    end

    it "encodes a short Array" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('[S')
      new_class_desc.serial_version = 0xef832e06e55db0fa
      new_class_desc.flags = 2
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_array.array_description.description = new_class_desc
      new_array.type = 'short'
      new_array.values = [-20, 65]

      expect(new_array.encode.unpack("C*")).to eq(short_array.unpack("C*"))
    end

    it "encodes a double Array" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('[D')
      new_class_desc.serial_version = 0x3ea68c14ab635a1e
      new_class_desc.flags = 2
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_array.array_description.description = new_class_desc
      new_array.type = 'double'
      new_array.values = [0.25, 0.21]

      expect(new_array.encode.unpack("C*")).to eq(double_array.unpack("C*"))
    end

    it "encodes a float Array" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('[F')
      new_class_desc.serial_version = 0xb9c818922e00c42
      new_class_desc.flags = 2
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_array.array_description.description = new_class_desc
      new_array.type = 'float'
      new_array.values = [1.0, 2.0]

      expect(new_array.encode.unpack("C*")).to eq(float_array.unpack("C*"))
    end

    it "encodes a int Array" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('[I')
      new_class_desc.serial_version = 0x4dba602676eab2a5
      new_class_desc.flags = 2
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_array.array_description.description = new_class_desc
      new_array.type = 'int'
      new_array.values = [-20, 65]

      expect(new_array.encode.unpack("C*")).to eq(int_array.unpack("C*"))
    end

    it "encodes a int Array" do
      new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
      new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new('[J')
      new_class_desc.serial_version = 0x782004b512b17593
      new_class_desc.flags = 2
      new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
      new_array.array_description.description = new_class_desc
      new_array.type = 'long'
      new_array.values = [-20, 65]

      expect(new_array.encode.unpack("C*")).to eq(long_array.unpack("C*"))
    end

  end

end