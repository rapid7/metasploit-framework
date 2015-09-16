# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::Utf do
  subject(:utf) do
    described_class.new
  end

  let(:sample_utf) { "\x00\x10java.lang.Number" }
  let(:sample_utf_io) { StringIO.new(sample_utf) }
  let(:empty_utf) { "\x00\x00" }
  let(:empty_utf_io) { StringIO.new(empty_utf) }
  let(:incomplete_utf) { "\x00\x10java.lang.Numb" }
  let(:incomplete_utf_io) { StringIO.new(incomplete_utf) }
  let(:empty_io) { StringIO.new('') }

  describe ".new" do
    it "Rex::Java::Serialization::Model::Utf" do
      expect(utf).to be_a(Rex::Java::Serialization::Model::Utf)
    end

    it "initializes length to 0" do
      expect(utf.length).to eq(0)
    end

    it "initializes contents with empty string" do
      expect(utf.contents).to be_empty
    end
  end

  describe "#encode" do
    context "when empty utf" do
      it { expect(utf.encode).to eq(empty_utf) }
    end

    context "when filled utf" do
      it do
        utf.length = 16
        utf.contents = 'java.lang.Number'
        expect(utf.encode).to eq(sample_utf)
      end
    end
  end

  describe "#decode" do
    context "when stream contains empty string" do
      it "raises Rex::Java::Serialization::DecodeError" do
        expect { utf.decode(empty_io) }.to raise_error(Rex::Java::Serialization::DecodeError)
      end
    end

    context "when stream contains empty utf" do
      it "returns a Rex::Java::Serialization::Model::Utf" do
        expect(utf.decode(empty_utf_io)).to be_a(Rex::Java::Serialization::Model::Utf)
      end

      it "sets length to 0" do
        utf.decode(empty_utf_io)
        expect(utf.length).to eq(0)
      end

      it "sets contents to empty string" do
        utf.decode(empty_utf_io)
        expect(utf.contents).to be_empty
      end
    end

    context "when stream contains incomplete utf" do
      it "raises Rex::Java::Serialization::DecodeError" do
        expect { utf.decode(incomplete_utf_io) }.to raise_error(Rex::Java::Serialization::DecodeError)
      end
    end

    context "when stream contains correct utf" do

      it "returns a Rex::Java::Serialization::Model::Utf" do
        expect(utf.decode(sample_utf_io)).to be_a(Rex::Java::Serialization::Model::Utf)
      end

      it "sets length to 0" do
        utf.decode(sample_utf_io)
        expect(utf.length).to eq(16)
      end

      it "sets contents to sample string" do
        utf.decode(sample_utf_io)
        expect(utf.contents).to eq('java.lang.Number')
      end
    end
  end

  describe "#to_s" do
    it "prints an stream containing a sample utf" do
      utf.decode(sample_utf_io)
      expect(utf.to_s).to eq('java.lang.Number')
    end

    it "prints an stream containing an empty utf" do
      utf.decode(empty_utf_io)
      expect(utf.to_s).to eq('')
    end
  end

end