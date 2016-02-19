# -*- coding:binary -*-
require 'spec_helper'
require 'rex/arch'

RSpec.describe Rex::Arch do
  describe ".pack_addr" do
    subject { described_class.pack_addr(arch, addr) }

    context "when arch is ARCH_ZARCH" do
      let(:arch) { ARCH_ZARCH }
      let(:addr) { 0xdeadbeefbe655321 }
      it "packs addr as 64-bit unsigned, big-endian" do
        is_expected.to eq("\xDE\xAD\xBE\xEF\xBEeS!")
      end
    end
  end
end
