require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::BlockData do
  subject(:block) do
    described_class.new
  end

  let(:sample_block) { "\x10\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" }
  let(:sample_block_io) { StringIO.new(sample_block) }
  let(:empty_block) { "\x00" }
  let(:empty_block_io) { StringIO.new(empty_block) }
  let(:incomplete_block) { "\x10\x01\x02\x03\x04\x05" }
  let(:incomplete_block_io) { StringIO.new(incomplete_block) }
  let(:empty_io) { StringIO.new('') }

  describe ".new" do
    it "Rex::Java::Serialization::Model::BlockData" do
      expect(block).to be_a(Rex::Java::Serialization::Model::BlockData)
    end

    it "initializes length to 0" do
      expect(block.length).to eq(0)
    end

    it "initializes contents with empty string" do
      expect(block.contents).to be_empty
    end
  end

  describe "#encode" do
    context "when empty block" do
      it { expect(block.encode).to eq(empty_block) }
    end

    context "when filled block" do
      it do
        block.length = 16
        block.contents = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        expect(block.encode).to eq(sample_block)
      end
    end
  end

  describe "#decode" do
    context "when stream contains empty string" do
      it "returns nil" do
        expect { block.decode(empty_io) }.to raise_error(::RuntimeError)
      end
    end

    context "when stream contains empty block" do
      it "returns a Rex::Java::Serialization::Model::BlockData" do
        expect(block.decode(empty_block_io)).to be_a(Rex::Java::Serialization::Model::BlockData)
      end

      it "sets length to 0" do
        block.decode(empty_block_io)
        expect(block.length).to eq(0)
      end

      it "sets contents to empty string" do
        block.decode(empty_block_io)
        expect(block.contents).to be_empty
      end
    end

    context "when stream contains incomplete block" do
      it "returns nil" do
        expect { block.decode(incomplete_block_io) }.to raise_error(::RuntimeError)
      end
    end

    context "when stream contains correct block" do

      it "returns a Rex::Java::Serialization::Model::BlockData" do
        expect(block.decode(sample_block_io)).to be_a(Rex::Java::Serialization::Model::BlockData)
      end

      it "sets length to 0" do
        block.decode(sample_block_io)
        expect(block.length).to eq(16)
      end

      it "sets contents to sample string" do
        block.decode(sample_block_io)
        expect(block.contents).to eq("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")
      end
    end
  end
end