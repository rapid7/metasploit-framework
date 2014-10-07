# -*- coding:binary -*-
require 'spec_helper'

require 'rex/arch'

describe Rex::Arch do

  describe ".adjust_stack_pointer" do
    subject { described_class.adjust_stack_pointer(arch, adjustment) }
    let(:adjustment) { 100 }

    context "when arch is ARCH_X86" do
      let(:arch) { ARCH_X86 }

      it "emits an ESP adjustment instruction" do
        is_expected.to be_a_kind_of(String)
      end
    end

    context "when arch isn't ARCH_X86" do
      let(:arch) { ARCH_FIREFOX }

      it "returns nil" do
        is_expected.to be_nil
      end
    end

    context "when arch is an array" do
      let(:arch) { [ARCH_X86, ARCH_FIREFOX] }

      it "uses the first arch in the array" do
        is_expected.to be_a_kind_of(String)
      end
    end
  end

  describe ".pack_addr" do
    subject { described_class.pack_addr(arch, addr) }

    context "when arch is ARCH_X86" do
      let(:arch) { ARCH_X86 }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, little-endian" do
        is_expected.to eq("DCBA")
      end
    end

    context "when arch is ARCH_X86_64" do
      let(:arch) { ARCH_X86_64 }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 62-bit unsigned, little-endian" do
        is_expected.to eq("HGFEDCBA")
      end
    end

    context "when arch is ARCH_X64" do
      let(:arch) { ARCH_X64 }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 62-bit unsigned, little-endian" do
        is_expected.to eq("HGFEDCBA")
      end
    end

    context "when arch is ARCH_MIPS" do
      let(:arch) { ARCH_MIPS }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_MIPSBE" do
      let(:arch) { ARCH_MIPSBE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_MIPSLE" do
      let(:arch) { ARCH_MIPSLE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, little-endian" do
        is_expected.to eq("DCBA")
      end
    end

    context "when arch is ARCH_PPC" do
      let(:arch) { ARCH_PPC }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_SPARC" do
      let(:arch) { ARCH_SPARC }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_ARMLE" do
      let(:arch) { ARCH_ARMLE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, little-endian" do
        is_expected.to eq("DCBA")
      end
    end

    context "when arch is ARCH_ARMBE" do
      let(:arch) { ARCH_ARMBE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is invalid" do
      let(:arch) { ARCH_FIREFOX }
      let(:addr) { 0x41424344 }

      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to be_nil
      end
    end

    context "when arch is an Array" do
      let(:arch) { [ARCH_ARMLE, ARCH_ARMBE, ARCH_X86_64] }
      let(:addr) { 0x41424344 }
      it "packs addr using the first architecture in the array" do
        is_expected.to eq("DCBA")
      end
    end
  end

  describe ".endian" do

    let(:endianesses) do
      {
        ARCH_X86 => ENDIAN_LITTLE,
        ARCH_X86_64 => ENDIAN_LITTLE,
        ARCH_MIPS => ENDIAN_BIG,
        ARCH_MIPSLE => ENDIAN_LITTLE,
        ARCH_MIPSBE => ENDIAN_BIG,
        ARCH_PPC => ENDIAN_BIG,
        ARCH_SPARC => ENDIAN_BIG,
        ARCH_ARMLE => ENDIAN_LITTLE,
        ARCH_ARMBE => ENDIAN_BIG
      }
    end
    subject { described_class.endian(arch) }

    context "when recognized arch" do
      it "returns its endianess" do
        endianesses.each_key do |arch|
          expect(described_class.endian(arch)).to eq(endianesses[arch])
        end
      end
    end

    context "when not recognized arch" do
      let(:arch) { ARCH_FIREFOX }
      it "returns ENDIAN_LITTLE" do
        is_expected.to eq(ENDIAN_LITTLE)
      end
    end

    context "when arch is an array" do
      let(:arch) { [ARCH_X86, ARCH_MIPSBE] }
      it "returns first arch endianess" do
        is_expected.to eq(ENDIAN_LITTLE)
      end
    end
  end
end
