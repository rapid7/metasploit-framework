# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'stringio'

RSpec.describe Rex::Java::Serialization::Model::Annotation do
  subject(:annotation) do
    described_class.new
  end

  let(:empty_contents) { "\x78" }
  let(:empty_contents_io) { StringIO.new(empty_contents) }
  let(:contents) { "\x77\x05\x01\x02\x03\x04\x05\x7a\x00\x00\x00\x05\x01\x02\x03\x04\x05\x78" }
  let(:contents_io) { StringIO.new(contents) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::Annotation" do
      expect(annotation).to be_a(Rex::Java::Serialization::Model::Annotation)
    end

    it "initializes contents with empty array" do
      expect(annotation.contents).to be_empty
    end
  end

  describe "#encode" do

    context "when empty contents" do
      it do
        annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
        expect(annotation.encode).to eq(empty_contents)
      end
    end

    context "when block data contents" do
      it do
        annotation.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x01\x02\x03\x04\x05")
        annotation.contents << Rex::Java::Serialization::Model::BlockDataLong.new(nil, "\x01\x02\x03\x04\x05")
        annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
        expect(annotation.encode).to eq(contents)
      end
    end

  end

  describe "#decode" do

    context "when empty contents" do
      it "returns a Rex::Java::Serialization::Model::Annotation" do
        expect(annotation.decode(empty_contents_io)).to be_a(Rex::Java::Serialization::Model::Annotation)
      end

      it "unserializes one content" do
        annotation.decode(empty_contents_io)
        expect(annotation.contents.length).to eq(1)
      end

      it "unserializes one EndBlockData content" do
        annotation.decode(empty_contents_io)
        expect(annotation.contents[0]).to be_a(Rex::Java::Serialization::Model::EndBlockData)
      end
    end

    context "when block data contents" do
      it "returns a Rex::Java::Serialization::Model::Annotation" do
        expect(annotation.decode(contents_io)).to be_a(Rex::Java::Serialization::Model::Annotation)
      end

      it "deserializes contents" do
        annotation.decode(contents_io)
        expect(annotation.contents.length).to eq(3)
      end

      it "deserializes block data contents" do
        annotation.decode(contents_io)
        expect(annotation.contents[0]).to be_a_kind_of(Rex::Java::Serialization::Model::BlockData)
      end

      it "deserializes block data long contents" do
        annotation.decode(contents_io)
        expect(annotation.contents[1]).to be_a_kind_of(Rex::Java::Serialization::Model::BlockDataLong)
      end

      it "deserializes end block data" do
        annotation.decode(contents_io)
        expect(annotation.contents[2]).to be_a_kind_of(Rex::Java::Serialization::Model::EndBlockData)
      end
    end

  end

  describe "#to_s" do
    it "prints an empty annotation" do
      annotation.decode(empty_contents_io)
      expect(annotation.to_s).to eq('[ EndBlockData ]')
    end

    it "prints an annotation with contents" do
      annotation.decode(contents_io)
      expect(annotation.to_s).to eq('[ BlockData { [ 0x1, 0x2, 0x3, 0x4, 0x5 ] }, BlockDataLong { [ 0x1, 0x2, 0x3, 0x4, 0x5 ] }, EndBlockData ]')
    end
  end

end