# -*- coding:binary -*-
require 'spec_helper'

require 'rex/encoder/nonalpha'

describe Rex::Encoder::NonAlpha do

  let(:decoder) do
    dec = "\x66\xB9\xFF\xFF" +
        "\xEB\x19"  +
        "\\\x5E"      +
        "\x8B\xFE"  +
        "\x83\xC7"  + "." +
        "\x8B\xD7"  +
        "\x3B\xF2"  +
        "\\\x7D\x0B"  +
        "\xB0\\\x7B"  +
        "\xF2\xAE"  +
        "\xFF\xCF"  +
        "\xAC"      +
        "\\\x28\x07"  +
        "\xEB\xF1"  +
        "\xEB"      + "." +
        "\xE8\xE2\xFF\xFF\xFF"
    Regexp.new(dec)
  end

  describe ".gen_decoder" do
    subject { described_class.gen_decoder }

    it "returns an String" do
      is_expected.to be_kind_of(String)
    end

    it "returns the decoder code" do
      p "#{described_class.gen_decoder}"
      is_expected.to match(decoder)
    end
  end

  describe ".encode_byte" do
    subject { described_class.encode_byte(block, table, tablelen) }

    context "when tablelen > 255" do
      let(:badchars) { "" }
      let(:block) { 0x20 }
      let(:table) { "" }
      let(:tablelen) { 256 }

      it "raises an error" do
        expect { subject }.to raise_error(RuntimeError)
      end
    end

    context "when block == 0x7b" do
      let(:badchars) { "" }
      let(:block) { 0x7b }
      let(:table) { "" }
      let(:tablelen) { 0 }

      it "raises an error" do
        expect { subject }.to raise_error(RuntimeError)
      end
    end

    context "when block == 0x40" do

    end
  end

end
