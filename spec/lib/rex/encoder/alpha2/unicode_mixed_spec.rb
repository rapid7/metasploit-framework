# -*- coding:binary -*-
require 'spec_helper'

require 'rex/encoder/alpha2/unicode_mixed'

describe Rex::Encoder::Alpha2::UnicodeMixed do

  it_behaves_like 'Rex::Encoder::Alpha2::Generic'

  let(:decoder_stub) do
    "jXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JB"
  end

  let(:reg_signature) do
    {
      'EAX' => 'PPYA',
      'ECX' => '4444',
      'EDX' => 'RRYA',
      'EBX' => 'SSYA',
      'ESP' => 'TUYA',
      'EBP' => 'UUYAs',
      'ESI' => 'VVYA',
      'EDI' => 'WWYA'
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
        expect { decoder_prefix }.to raise_error(RuntimeError)
      end
    end

    context "when offset is bigger than 21" do
      let(:reg) { 'ECX' }
      let(:offset) { 22 }

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
        expect { decoder }.to raise_error(RuntimeError)
      end
    end

    context "when offset is bigger than 21" do
      let(:reg) { 'ECX' }
      let(:offset) { 22 }

      it "raises an error" do
        expect { decoder }.to raise_error
      end
    end
  end

end
