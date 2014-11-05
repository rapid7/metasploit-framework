# -*- coding:binary -*-
require 'spec_helper'

require 'rex/encoder/alpha2/generic'

describe Rex::Encoder::Alpha2::Generic do

  it_behaves_like 'Rex::Encoder::Alpha2::Generic'

  describe ".default_accepted_chars" do
    subject(:accepted_chars) { described_class.default_accepted_chars }

    it { is_expected.to eq(('a' .. 'z').to_a + ('B' .. 'Z').to_a + ('0' .. '9').to_a) }
  end

  describe ".gen_decoder_prefix" do
    subject(:decoder_prefix) { described_class.gen_decoder_prefix(reg, offset) }
    let(:reg) { 'ECX' }
    let(:offset) { 0 }

    it { is_expected.to eq('') }
  end

  describe ".gen_decoder" do
    subject(:decoder) { described_class.gen_decoder(reg, offset) }
    let(:reg) { 'ECX' }
    let(:offset) { 0 }

    it { is_expected.to eq('') }
  end

  describe ".gen_second" do
    subject(:second) { described_class.gen_second(block, base) }
    let(:block) { 0xaf }
    let(:base) { 0xfa }

    it "returns block ^ base" do
      expect(second ^ base).to eq(block)
    end
  end

end
