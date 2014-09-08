# -*- coding:binary -*-
require 'spec_helper'

require 'rex/encoder/xdr'

describe Rex::Encoder::XDR do

  describe ".encode_int" do
    subject { described_class.encode_int(int) }
    let(:int) { 0x41424344 }

    it "returns an String" do
      is_expected.to be_kind_of(String)
    end

    it "encodes big endian 32 bit usigned integer" do
      is_expected.to eq("\x41\x42\x43\x44")
    end
  end

  describe ".decode_int!" do
    subject { described_class.decode_int!(data) }

    context "when data is nil" do
      let(:data) { nil }
      it "returns 0" do
        is_expected.to be(0)
      end
    end

    context "when data is empty" do
      let(:data) { '' }

      it "returns nil" do
        is_expected.to be_nil
      end
    end

    context "when data is 1-4 bytes length" do
      let(:data) { "\x41\x42\x43\x44" }

      it "unpacks big endian 32bit unsigned int" do
        is_expected.to eq(0x41424344)
      end
    end

    context "when data is bigger than 4 bytes" do
      let(:data) { "\x41\x42\x43\x44\x45" }

      it "unpacks just one big endian 32bit unsigned int" do
        is_expected.to eq(0x41424344)
      end
    end
  end

  describe ".encode_lchar" do
    subject { described_class.encode_lchar(char) }

    context "when char & 0x80 == 0" do
      let(:char) { 0x80 }

      it "encodes char byte as signed extended big endian 32 bit integer" do
        is_expected.to eq("\xff\xff\xff\x80")
      end
    end

    context "when char & 0x80 != 0" do
      let(:char) { 0x41 }

      it "encodes char byte as signed extended big endian 32 bit integer" do
        is_expected.to eq("\x00\x00\x00\x41")
      end
    end
  end

  describe ".decode_lchar!" do
    subject { described_class.decode_lchar!(data) }

    context "when data's length is equal or greater than 4" do
      let(:data) { "\x41\x42\x43\x44" }

      it "returns char code for last byte" do
        is_expected.to eq("D")
      end
    end

    context "when data's length is less than 4" do
      let(:data) { "\x41" }

      it "raises an error" do
        expect { subject }.to raise_error(NoMethodError)
      end
    end
  end

  describe ".encode_string" do
    subject { described_class.encode_string(str, max) }

    context "when data is bigger than max" do
      let(:str) { "ABCDE" }
      let(:max) { 4 }

      it "raises an error" do
        expect { subject }.to raise_error(ArgumentError)
      end
    end

    context "when data is shorter or equal to max" do
      let(:str) { "ABCDE" }
      let(:max) { 5 }

      it "returns an String" do
        is_expected.to be_kind_of(String)
      end

      it "prefix encoded length" do
        is_expected.to start_with("\x00\x00\x00\x05")
      end

      it "returns the encoded string padded with zeros" do
        is_expected.to eq("\x00\x00\x00\x05ABCDE\x00\x00\x00")
      end
    end
  end

  describe ".decode_string!" do
    subject { described_class.decode_string!(data) }

    context "when encoded string length is 0" do
      let(:data) { "\x00\x00\x00\x00" }

      it "returns empty string" do
        is_expected.to eq("")
      end
    end

    context "when string contains padding" do
      let(:data) {"\x00\x00\x00\x03ABC00000"}

      it "returns string without padding" do
        is_expected.to eq("ABC")
      end
    end

    context "when fake string length" do
      let(:data) { "\x00\x00\x00\x03" }

      it "returns empty string" do
        is_expected.to eq("")
      end
    end

    context "when encoded string length is longer than real string length" do
      let(:data) { "\x00\x00\x00\x08ABCD" }

      it "returns available string" do
        is_expected.to eq("ABCD")
      end
    end
  end
end
