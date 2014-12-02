require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::LongUtf do
  subject(:long_utf) do
    described_class.new
  end

  let(:sample_utf) { "\x00\x00\x00\x00\x00\x00\x00\x10java.lang.Number" }
  let(:sample_utf_io) { StringIO.new(sample_utf) }
  let(:empty_utf) { "\x00\x00\x00\x00\x00\x00\x00\x00" }
  let(:empty_utf_io) { StringIO.new(empty_utf) }
  let(:incomplete_utf) { "\x00\x00\x00\x00\x00\x00\x00\x10java.lang.Numb" }
  let(:incomplete_utf_io) { StringIO.new(incomplete_utf) }
  let(:empty_io) { StringIO.new('') }

  describe ".new" do
    it "Rex::Java::Serialization::Model::LongUtf" do
      expect(long_utf).to be_a(Rex::Java::Serialization::Model::LongUtf)
    end

    it "initializes length to 0" do
      expect(long_utf.length).to eq(0)
    end

    it "initializes contents with empty string" do
      expect(long_utf.contents).to be_empty
    end
  end

  describe "#encode" do
    context "when empty long_utf" do
      it { expect(long_utf.encode).to eq(empty_utf) }
    end

    context "when filled utf" do
      it do
        long_utf.length = 16
        long_utf.contents = 'java.lang.Number'
        expect(long_utf.encode).to eq(sample_utf)
      end
    end
  end

  describe "#decode" do
    context "when stream contains empty string" do
      it "returns nil" do
        expect(long_utf.decode(empty_io)).to be_nil
      end
    end

    context "when stream contains empty long_utf" do
      it "returns a Rex::Java::Serialization::Model::LongUtf" do
        expect(long_utf.decode(empty_utf_io)).to be_a(Rex::Java::Serialization::Model::LongUtf)
      end

      it "sets length to 0" do
        long_utf.decode(empty_utf_io)
        expect(long_utf.length).to eq(0)
      end

      it "sets contents to empty string" do
        long_utf.decode(empty_utf_io)
        expect(long_utf.contents).to be_empty
      end
    end

    context "when stream contains incomplete long_utf" do
      it "returns nil" do
        expect(long_utf.decode(incomplete_utf_io)).to be_nil
      end
    end

    context "when stream contains correct long_utf" do

      it "returns a Rex::Java::Serialization::Model::LongUtf" do
        expect(long_utf.decode(sample_utf_io)).to be_a(Rex::Java::Serialization::Model::LongUtf)
      end

      it "sets length to 0" do
        long_utf.decode(sample_utf_io)
        expect(long_utf.length).to eq(16)
      end

      it "sets contents to sample string" do
        long_utf.decode(sample_utf_io)
        expect(long_utf.contents).to eq('java.lang.Number')
      end
    end
  end

  describe ".decode" do
    context "when stream contains empty string" do
      it "returns nil" do
        expect(described_class.decode(empty_io)).to be_nil
      end
    end

    context "when stream contains empty long_utf" do
      it "returns a Rex::Java::Serialization::Model::LongUtf" do
        expect(described_class.decode(empty_utf_io)).to be_a(Rex::Java::Serialization::Model::LongUtf)
      end

      it "sets length to 0" do
        long_utf = described_class.decode(empty_utf_io)
        expect(long_utf.length).to eq(0)
      end

      it "sets contents to empty string" do
        long_utf = described_class.decode(empty_utf_io)
        expect(long_utf.contents).to be_empty
      end
    end

    context "when stream contains incomplete utf" do
      it "returns nil" do
        expect(described_class.decode(incomplete_utf_io)).to be_nil
      end
    end

    context "when stream contains correct long_utf" do
      it "returns a Rex::Java::Serialization::Model::LongUtf" do
        expect(described_class.decode(sample_utf_io)).to be_a(Rex::Java::Serialization::Model::LongUtf)
      end

      it "sets length to 0" do
        long_utf = described_class.decode(sample_utf_io)
        expect(long_utf.length).to eq(16)
      end

      it "sets contents to sample string" do
        long_utf = described_class.decode(sample_utf_io)
        expect(long_utf.contents).to eq('java.lang.Number')
      end
    end
  end
end