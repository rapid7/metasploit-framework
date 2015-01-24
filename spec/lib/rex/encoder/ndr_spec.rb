# -*- coding:binary -*-
require 'spec_helper'

require 'rex/encoder/ndr'

describe Rex::Encoder::NDR do

  describe ".align" do
    subject { described_class.align(string) }

    context "when empty string argument" do
      let(:string) { "" }
      it { is_expected.to eq("") }
    end

    context "when 32bit aligned length argument" do
      let(:string) { "A" * 4 }
      it { is_expected.to eq("") }
    end

    context "when 32bit unaligned length argument" do
      let(:string) { "A" * 5 }
      it "returns the padding, as null bytes, necessary to 32bit align the argument" do
        is_expected.to eq("\x00\x00\x00")
      end
    end
  end

  describe ".long" do
    subject { described_class.long(string) }
    let(:string) { 0x41424344 }

    it "encodes the arguments as 32-bit little-endian unsigned integer" do
      is_expected.to eq("\x44\x43\x42\x41")
    end

    context "when argument bigger than 32-bit unsigned integer" do
      let(:string) { 0x4142434445 }
      it "truncates the argument" do
        is_expected.to eq("\x45\x44\x43\x42")
      end
    end
  end

  describe ".short" do
    subject { described_class.short(string) }
    let(:string) { 0x4142 }

    it "encodes the arguments as 16-bit little-endian unsigned integer" do
      is_expected.to eq("\x42\x41")
    end

    context "when argument bigger than 16-bit unsigned integer" do
      let(:string) { 0x41424344 }
      it "truncates the argument" do
        is_expected.to eq("\x44\x43")
      end
    end

  end

  describe ".byte" do
    subject { described_class.byte(string) }
    let(:string) { 0x41 }

    it "encodes the arguments as 8-bit unsigned integer" do
      is_expected.to eq("\x41")
    end

    context "when argument bigger than 8-bit unsigned integer" do
      let(:string) { 0x4142 }
      it "truncates the argument" do
        is_expected.to eq("\x42")
      end
    end

  end

  describe ".UniConformantArray" do
    subject { described_class.UniConformantArray(string) }
    let(:string) { "ABCDE" }

    it "returns the encoded string" do
      is_expected.to be_kind_of(String)
    end

    it "starts encoding the string length as 32-bit little-endian unsigned integer" do
      expect(subject.unpack("V").first).to eq(string.length)
    end

    it "adds the string argument" do
      is_expected.to include(string)
    end

    it "ends with padding to make result length 32-bits aligned" do
      is_expected.to end_with("\x00" * 3)
    end
  end

  describe ".string" do
    subject { described_class.string(string) }
    let(:string) { "ABCD" }

    it "returns the encoded string" do
      is_expected.to be_kind_of(String)
      expect(subject.length).to eq(20)
    end

    it "starts encoding string metadata" do
      expect(subject.unpack("VVV")[0]).to eq(string.length)
      expect(subject.unpack("VVV")[1]).to eq(0)
      expect(subject.unpack("VVV")[2]).to eq(string.length)
    end

    it "adds the string argument null-byte terminated" do
      is_expected.to include("ABCD\x00")
    end

    it "ends with padding to make result length 32-bits aligned" do
      is_expected.to end_with("\x00" * 3)
    end
  end

  describe ".wstring" do
    subject { described_class.wstring(string) }

    it_behaves_like "Rex::Encoder::NDR.wstring"
  end

  describe ".UnicodeConformantVaryingString" do
    subject { described_class.UnicodeConformantVaryingString(string) }

    it_behaves_like "Rex::Encoder::NDR.wstring"
  end

  describe ".uwstring" do
    subject { described_class.uwstring(string) }

    let(:string) { "ABCD" }

    it "encodes the argument as null-terminated unicode string" do
      is_expected.to include("A\x00B\x00C\x00D\x00\x00\x00")
    end

    it "starts encoding string metadata" do
      expect(subject.unpack("VVVV")[1]).to eq(string.length + 1)
      expect(subject.unpack("VVVV")[2]).to eq(0)
      expect(subject.unpack("VVVV")[3]).to eq(string.length + 1)
    end

    it "ends with padding to make result length 32-bits aligned" do
      is_expected.to end_with("\x00" * 2)
      expect(subject.length).to eq(28)
    end
  end

  describe ".wstring_prebuilt" do
    subject { described_class.wstring_prebuilt(string) }

    it_behaves_like "Rex::Encoder::NDR.wstring_prebuild"
  end

  describe ".UnicodeConformantVaryingStringPreBuilt" do
    subject { described_class.UnicodeConformantVaryingStringPreBuilt(string) }

    it_behaves_like "Rex::Encoder::NDR.wstring_prebuild"
  end

end
