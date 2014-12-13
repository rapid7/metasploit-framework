# -*- coding:binary -*-
require 'spec_helper'

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
      it "raises RuntimeError" do
        expect { long_utf.decode(empty_io) }.to raise_error(::RuntimeError)
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
        expect { long_utf.decode(incomplete_utf_io) }.to raise_error(::RuntimeError)
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

    describe "#to_s" do
      it "prints an stream containing a sample long utf" do
        long_utf.decode(sample_utf_io)
        expect(long_utf.to_s).to eq('java.lang.Number')
      end

      it "prints an stream containing an empty long utf" do
        long_utf.decode(empty_utf_io)
        expect(long_utf.to_s).to eq('')
      end
    end
  end

end