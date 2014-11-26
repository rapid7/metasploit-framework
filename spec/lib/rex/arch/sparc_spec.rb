# -*- coding:binary -*-
require 'spec_helper'

require 'rex/arch/sparc'

describe Rex::Arch::Sparc do

  describe ".sethi" do
    subject { described_class.sethi(constant, dst) }

    let(:constant) { 0 }

    context "when valid dst register" do
      let(:dst) { 'g3' }

      it "returns an String" do
        is_expected.to be_kind_of(String)
      end

      it "returns a 4 bytes length String" do
        expect(subject.length).to eq(4)
      end

      it "encodes a valid sethi instruction" do
        is_expected.to eq("\x07\x00\x00\x00")
      end
    end

    context "when invalid dst register" do
      let(:dst) { 'error' }

      it "raises an error" do
        expect { subject }.to raise_error(NameError)
      end
    end
  end

  describe ".ori" do
    subject { described_class.ori(src, constant, dst) }

    let(:constant) { 0 }

    context "when valid registers" do
      let(:src) { 'g5' }
      let(:dst) { 'g3' }

      it "returns an String" do
        is_expected.to be_kind_of(String)
      end

      it "returns a 4 bytes length String" do
        expect(subject.length).to eq(4)
      end

      it "encodes a valid ori instruction" do
        is_expected.to eq("\x86\x11\x60\x00")
      end
    end

    context "when invalid src register" do
      let(:src) { 'invalid' }
      let(:dst) { 'g3' }

      it "raises an error" do
        expect { subject }.to raise_error(NameError)
      end
    end

    context "when invalid dst register" do
      let(:src) { 'g5' }
      let(:dst) { 'invalid' }

      it "raises an error" do
        expect { subject }.to raise_error(NameError)
      end
    end
  end

  describe ".set" do
    subject { described_class.set(constant, dst) }

    context "when invalid dst register" do
      let(:constant) { 0 }
      let(:dst) { 'error' }

      it "raises an error" do
        expect { subject }.to raise_error(NameError)
      end
    end

    context "when constant <= 4095 and constant >= 0" do
      let(:constant) { 0 }
      let(:dst) { 'g3' }

      it "uses ori instruction" do
        expect(described_class).to receive(:ori).and_call_original
        is_expected.to eq("\x86\x10\x20\x00")
      end
    end

    context "when constant & 0x3ff != 0" do
      let(:constant) { 0x1001 }
      let(:dst) { 'g3' }

      it "uses set dword instruction" do
        expect(described_class).to receive(:set_dword).and_call_original
        is_expected.to eq("\x07\x00\x00\x04\x86\x10\xe0\x01")
      end
    end

    context "when other constant" do
      let(:constant) { 0x1c00 }
      let(:dst) { 'g3' }

      it "uses sethi instruction" do
        expect(described_class).to receive(:sethi).and_call_original
        is_expected.to eq("\x07\x00\x00\x07")
      end
    end
  end

  describe ".set_dword" do
    subject { described_class.set_dword(constant, dst) }

    let(:constant) { 0x1001 }

    context "when valid dst register" do
      let(:dst) { 'g3' }

      it "returns an String" do
        is_expected.to be_kind_of(String)
      end

      it "returns a 8 bytes length String" do
        expect(subject.length).to eq(8)
      end

      it "encodes a valid sequence of sethi and ori instructions" do
        is_expected.to eq("\x07\x00\x00\x04\x86\x10\xe0\x01")
      end
    end

    context "when invalid dst register" do
      let(:dst) { 'error' }

      it "raises an error" do
        expect { subject }.to raise_error(NameError)
      end
    end
  end


end
