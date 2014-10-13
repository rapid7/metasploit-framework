# -*- coding:binary -*-
require 'spec_helper'

require 'rex/encoder/alpha2/unicode_upper'

describe Rex::Encoder::Alpha2::UnicodeUpper do

  it_behaves_like 'Rex::Encoder::Alpha2::Generic'

  let(:decoder_stub) do
    "QATAXAZAPU3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JB"
  end

  let(:reg_signature) do
    {
      'EAX' => 'PPYA',
      'ECX' => '4444',
      'EDX' => 'RRYA',
      'EBX' => 'SSYA',
      'ESP' => 'TUYA',
      'EBP' => 'UUYA',
      'ESI' => 'VVYA',
      'EDI' => 'WWYA'
    }
  end

  describe ".default_accepted_chars" do
    subject(:accepted_chars) { described_class.default_accepted_chars }

    it { is_expected.to eq(('B' .. 'Z').to_a + ('0' .. '9').to_a) }
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
        expect(decoder_prefix).to be_nil
      end
    end

    context "when offset is bigger than 6" do
      let(:reg) { 'ECX' }
      let(:offset) { 7 }

      it "raises an error" do
        expect { decoder_prefix }.to raise_error(RuntimeError)
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
        expect { decoder }.to raise_error(NoMethodError)
      end
    end

    context "when offset is bigger than 6" do
      let(:reg) { 'ECX' }
      let(:offset) { 7 }

      it "raises an error" do
        expect { decoder }.to raise_error(RuntimeError)
      end
    end
  end

end
