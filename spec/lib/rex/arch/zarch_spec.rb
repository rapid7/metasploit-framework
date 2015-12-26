# -*- coding:binary -*-
require 'spec_helper'
require 'rex/arch'

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
RSpec.describe Rex::Arch do
=======
describe Rex::Arch do
>>>>>>> origin/4.11.2_release_pre-rails4
=======
describe Rex::Arch do
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
describe Rex::Arch do
>>>>>>> origin/msf-complex-payloads
=======
describe Rex::Arch do
>>>>>>> origin/msf-complex-payloads
=======
describe Rex::Arch do
>>>>>>> origin/payload-generator.rb
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
