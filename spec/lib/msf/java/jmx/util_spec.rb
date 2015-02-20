# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/java'
require 'msf/java/jmx'

describe Msf::Java::Jmx::Util do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Java::Jmx
    mod.send(:initialize)
    mod
  end

  let(:empty) { '' }
  let(:empty_io) { StringIO.new(empty) }
  let(:string) { "\x00\x04\x41\x42\x43\x44" }
  let(:string_io) { StringIO.new(string) }
  let(:int) { "\x00\x00\x00\x04" }
  let(:int_io) { StringIO.new(int) }
  let(:stream_raw) do
    "\xac\xed\x00\x05\x77\x22\x7b\xb5\x91\x73\x69\x12\x77\xcb\x4a\x7d" +
    "\x3f\x10\x00\x00\x01\x4a\xe3\xed\x2f\x53\x81\x03\xff\xff\xff\xff" +
    "\x60\x73\xb3\x36\x1f\x37\xbd\xc2\x73\x72\x00\x1b\x6a\x61\x76\x61" +
    "\x78\x2e\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2e\x4f\x62\x6a" +
    "\x65\x63\x74\x4e\x61\x6d\x65\x0f\x03\xa7\x1b\xeb\x6d\x15\xcf\x03" +
    "\x00\x00\x70\x78\x70\x74\x00\x1d\x4d\x4c\x65\x74\x43\x6f\x6d\x70" +
    "\x72\x6f\x6d\x69\x73\x65\x3a\x6e\x61\x6d\x65\x3d\x65\x76\x69\x6c" +
    "\x2c\x69\x64\x3d\x31\x78\x70"
  end
  let(:stream) { Rex::Java::Serialization::Model::Stream.decode(StringIO.new(stream_raw)) }

  let(:contents_unicast_ref) do
    "\x00\x0a\x55\x6e\x69\x63\x61\x73\x74\x52\x65\x66\x00\x0e\x31\x37" +
    "\x32\x2e\x31\x36\x2e\x31\x35\x38\x2e\x31\x33\x31\x00\x00\x0b\xf1" +
    "\x54\x74\xc4\x27\xb7\xa3\x4e\x9b\x51\xb5\x25\xf9\x00\x00\x01\x4a" +
    "\xdf\xd4\x57\x7e\x80\x01\x01"
  end
  let(:unicast_ref_io) do
    StringIO.new(Rex::Java::Serialization::Model::BlockData.new(nil, contents_unicast_ref).contents)
  end
  let(:unicast_ref) do
    {
      :address => '172.16.158.131',
      :id => "\x54\x74\xc4\x27\xb7\xa3\x4e\x9b\x51\xb5\x25\xf9\x00\x00\x01\x4a\xdf\xd4\x57\x7e\x80\x01\x01",
      :port => 3057
    }
  end


  describe "#extract_string" do
    context "when io contains a valid string" do
      it "returns the string" do
        expect(mod.extract_string(string_io)).to eq('ABCD')
      end
    end

    context "when io doesn't contain a valid string" do
      it "returns nil" do
        expect(mod.extract_string(empty_io)).to be_nil
      end
    end
  end

  describe "#extract_int" do
    context "when io contains a valid int" do
      it "returns the string" do
        expect(mod.extract_int(int_io)).to eq(4)
      end
    end

    context "when io doesn't contain a valid int" do
      it "returns nil" do
        expect(mod.extract_int(empty_io)).to be_nil
      end
    end
  end

  describe "#extract_object" do
    context "when empty stream" do
      it "returns nil" do
        empty_stream = Rex::Java::Serialization::Model::Stream.new
        expect(mod.extract_object(empty_stream, 1)). to be_nil
      end
    end

    context "when valid stream" do
      context "when id stores an object" do
        it "returns the object's class name" do
          expect(mod.extract_object(stream, 1)).to eq('javax.management.ObjectName')
        end
      end

      context "when id doesn't store an object" do
        it "returns nil" do
          expect(mod.extract_object(stream, 0)). to be_nil
        end
      end
    end
  end

  describe "#extract_unicast_ref" do
    context "when empty io" do
      it "returns nil" do
        expect(mod.extract_unicast_ref(empty_io)). to be_nil
      end
    end

    context "when valid io" do
      it "returns a hash" do
        expect(mod.extract_unicast_ref(unicast_ref_io)).to be_a(Hash)
      end

      it "returns a hash containing the UnicastRef information" do
        expect(mod.extract_unicast_ref(unicast_ref_io)).to eq(unicast_ref)
      end
    end
  end
end

