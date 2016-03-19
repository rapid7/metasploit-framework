# -*- coding:binary -*-
require 'spec_helper'

require 'rex/encoder/xdr'

RSpec.describe Rex::Encoder::XDR do

  describe ".encode_int" do
    subject(:encoded_int) { described_class.encode_int(int) }
    let(:int) { 0x41424344 }

    it "returns an String" do
      is_expected.to be_kind_of(String)
    end

    it "encodes big endian 32 bit usigned integer" do
      is_expected.to eq("\x41\x42\x43\x44")
    end
  end

  describe ".decode_int!" do
    subject(:decoded_int) { described_class.decode_int!(data) }

    context "when data is nil" do
      let(:data) { nil }
      it "raises an error" do
        expect { decoded_int }.to raise_error(ArgumentError)
      end
    end

    context "when data is empty" do
      let(:data) { '' }

      it "raises an error" do
        expect { decoded_int }.to raise_error(ArgumentError)
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
    subject(:encoded_lchar) { described_class.encode_lchar(char) }

    context "when char & 0x80 == 0" do
      let(:char) { 0x80 }

      it "encodes char byte as integer with sign extended" do
        is_expected.to eq("\xff\xff\xff\x80")
      end
    end

    context "when char & 0x80 != 0" do
      let(:char) { 0x41 }

      it "encodes char byte as integer" do
        is_expected.to eq("\x00\x00\x00\x41")
      end
    end
  end

  describe ".decode_lchar!" do
    subject(:decoded_lchar) { described_class.decode_lchar!(data) }

    context "when data's length is equal or greater than 4" do
      let(:data) { "\x41\x42\x43\x44" }

      it "returns char code for last byte" do
        is_expected.to eq("D")
      end
    end

    context "when data's length is less than 4" do
      let(:data) { "\x41" }

      it "raises an error" do
        expect { decoded_lchar }.to raise_error(ArgumentError)
      end
    end
  end

  describe ".encode_string" do
    subject(:encoded_string) { described_class.encode_string(str, max) }

    context "when data is bigger than max" do
      let(:str) { "ABCDE" }
      let(:max) { 4 }

      it "raises an error" do
        expect { encoded_string }.to raise_error(ArgumentError)
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
    subject(:decoded_string) { described_class.decode_string!(data) }

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

    context "when fake length" do
      context "and no string" do
        let(:data) { "\x00\x00\x00\x03" }

        it "returns empty string" do
          is_expected.to eq("")
        end
      end

      context "longer than real string length" do
        let(:data) { "\x00\x00\x00\x08ABCD" }

        it "returns available string" do
          is_expected.to eq("ABCD")
        end
      end
    end
  end

  describe ".encode_varray" do
    subject(:encoded_varray) { described_class.encode_varray(arr, max) }

    context "when arr length is bigger than max" do
      let(:arr) { [1, 2, 3] }
      let(:max) { 2 }
      it "raises an error" do
        expect { encoded_varray }.to raise_error(ArgumentError)
      end
    end

    context "when arr length is minor or equal than max" do
      let(:arr) { [0x41414141, 0x42424242, 0x43434343] }
      let(:max) { 3 }

      it "returns an String" do
        expect(described_class.encode_varray(arr, max) { |i| described_class.encode_int(i) }).to be_kind_of(String)
      end

      it "prefixes encoded length" do
        expect(described_class.encode_varray(arr, max) { |i| described_class.encode_int(i) }).to start_with("\x00\x00\x00\x03")
      end

      it "returns the encoded array" do
        expect(described_class.encode_varray(arr, max) { |i| described_class.encode_int(i) }).to eq("\x00\x00\x00\x03\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43")
      end
    end
  end

  describe ".decode_varray!" do
    subject(:decoded_varray) { described_class.decode_varray!(data) }

    context "when encoded length is 0" do
      let(:data) { "\x00\x00\x00\x00" }

      it "returns an empty array" do
        is_expected.to eq([])
      end
    end

    context "when fake encoded length" do
      context "and no values" do
        let(:data) { "\x00\x00\x00\x02" }

        it "raises an error" do
          expect { described_class.decode_varray!(data) { |s| described_class.decode_int!(s) } }.to raise_error(ArgumentError)
        end
      end

      context "longer than available values" do
        let(:data) { "\x00\x00\x00\x02\x00\x00\x00\x41" }

        it "raises an error" do
          expect { described_class.decode_varray!(data) { |s| described_class.decode_int!(s) } }.to raise_error(ArgumentError)
        end
      end
    end

    context "when valid encoded data" do
      let(:data) { "\x00\x00\x00\x02\x41\x42\x43\x44\x00\x00\x00\x11"}
      it "retuns Array with decoded values" do
        expect(described_class.decode_varray!(data) { |s| described_class.decode_int!(s) }).to eq([0x41424344, 0x11])
      end
    end
  end

  describe ".encode" do
    it "encodes integers" do
      expect(described_class.encode(1)).to eq("\x00\x00\x00\x01")
    end

    it "encodes arrays" do
      expect(described_class.encode([0x41414141, 0x42424242])).to eq("\x00\x00\x00\x02\x41\x41\x41\x41\x42\x42\x42\x42")
    end

    it "encodes strings" do
      expect(described_class.encode("ABCD")).to eq("\x00\x00\x00\x04\x41\x42\x43\x44")
    end

    it "encodes mixed type of elements" do
      expect(described_class.encode(1, [0x41414141], "ABCD")).to eq("\x00\x00\x00\x01\x00\x00\x00\x01\x41\x41\x41\x41\x00\x00\x00\x04\x41\x42\x43\x44")
    end
  end

  describe ".decode!" do

    context "when no type arguments" do
      it "retuns empty Array" do
        expect(described_class.decode!("\x41\x41\x41\x41")).to eq([])
      end
    end

    context "when not enough data" do
      it "retuns Array filled with nils" do
        expect(described_class.decode!("", Array)).to eq([nil])
      end
    end

    it "decodes integers" do
      expect(described_class.decode!("\x41\x41\x41\x41", Integer)).to eq([0x41414141])
    end

    it "decodes arrays" do
      expect(described_class.decode!("\x00\x00\x00\x01\x41\x41\x41\x41", [Integer])).to eq([[0x41414141]])
    end

    it "decodes strings" do
      expect(described_class.decode!("\x00\x00\x00\x01\x41", String)).to eq(["A"])
    end

    it "decodes mixed elements" do
      expect(described_class.decode!("\x41\x41\x41\x41\x00\x00\x00\x01\x41\x00\x00\x00\x00\x00\x00\x01\x42\x42\x42\x42", Integer, String, [Integer])).to eq([0x41414141, "A", [0x42424242]])
    end
  end

end
