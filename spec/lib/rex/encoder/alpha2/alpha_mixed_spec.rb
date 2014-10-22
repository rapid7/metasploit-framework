# -*- coding:binary -*-
require 'spec_helper'

require 'rex/encoder/alpha2/alpha_mixed'

describe Rex::Encoder::Alpha2::AlphaMixed do

  it_behaves_like 'Rex::Encoder::Alpha2::Generic'

  let(:decoder_stub) do
    "jAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI"
  end

  let(:reg_signature) do
    {
      'EAX' => 'PY',
      'ECX' => 'I',
      'EDX' => '7RY',
      'EBX' => 'SY',
      'ESP' => 'TY',
      'EBP' => 'UY',
      'ESI' => 'VY',
      'EDI' => 'WY'
    }
  end

  describe ".gen_decoder_prefix" do
    subject(:decoder_prefix) { described_class.gen_decoder_prefix(reg, offset) }
    let(:reg) { 'ECX' }
    let(:offset) { 5 }

    it "returns decoder prefix" do
      is_expected.to include(reg_signature[reg])
    end

    context "when invalid reg name" do
      let(:reg) { 'NON EXISTENT' }
      let(:offset) { 0 }

      it "raises an error" do
        expect { decoder_prefix }.to raise_error(ArgumentError)
      end
    end

    context "when offset is bigger than 32" do
      let(:reg) { 'ECX' }
      let(:offset) { 33 }

      it "raises an error" do
        expect { decoder_prefix }.to raise_error
      end
    end
  end


  describe ".gen_decoder" do
    subject(:decoder) { described_class.gen_decoder(reg, offset) }
    let(:reg) { 'ECX' }
    let(:offset) { 5 }

    it "returns the alpha upper decoder" do
      is_expected.to include(decoder_stub)
    end

    it "uses the correct decoder prefix" do
      is_expected.to include(reg_signature[reg])
    end

    context "when invalid reg name" do
      let(:reg) { 'NON EXISTENT' }
      let(:offset) { 0 }

      it "raises an error" do
        expect { decoder }.to raise_error(ArgumentError)
      end
    end

    context "when offset is bigger than 32" do
      let(:reg) { 'ECX' }
      let(:offset) { 33 }

      it "raises an error" do
        expect { decoder }.to raise_error
      end
    end
  end

end
