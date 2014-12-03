require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::Annotation do
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
        expect(annotation.encode).to eq(empty_contents)
      end
    end

    context "when block data contents" do
      it do
        annotation.contents << Rex::Java::Serialization::Model::BlockData.new("\x01\x02\x03\x04\x05")
        annotation.contents << Rex::Java::Serialization::Model::BlockDataLong.new("\x01\x02\x03\x04\x05")
        expect(annotation.encode).to eq(contents)
      end
    end

  end

  describe "#decode" do

    context "when empty contents" do
      it "returns a Rex::Java::Serialization::Model::Annotation" do
        expect(annotation.decode(empty_contents_io)).to be_a(Rex::Java::Serialization::Model::Annotation)
      end

      it "keeps contents" do
        annotation.decode(empty_contents_io)
        expect(annotation.contents).to be_empty
      end
    end

    context "when block data contents" do
      it "returns a Rex::Java::Serialization::Model::Annotation" do
        expect(annotation.decode(contents_io)).to be_a(Rex::Java::Serialization::Model::Annotation)
      end

      it "deserializes contents" do
        annotation.decode(contents_io)
        expect(annotation.contents.length).to eq(2)
      end

      it "deserializes block data contents" do
        annotation.decode(contents_io)
        expect(annotation.contents[0]).to be_a_kind_of(Rex::Java::Serialization::Model::BlockData)
      end

      it "deserializes block data long contents" do
        annotation.decode(contents_io)
        expect(annotation.contents[1]).to be_a_kind_of(Rex::Java::Serialization::Model::BlockDataLong)
      end
    end

  end
end