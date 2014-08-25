# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/encryptjs'

describe Rex::Arch::X86 do

  describe ".reg_number" do

    subject { described_class.reg_number(register) }

    context "when valid argument" do
      context "in upcase" do
        let(:register) { "EAX" }
        it { is_expected.to eq(Rex::Arch::X86::EAX) }
      end

      context "in downcase" do
        let(:register) { "esi" }
        it { is_expected.to eq(Rex::Arch::X86::ESI) }
      end
    end

    context "when invalid argument" do
      let(:register) { "non_existent" }
      it "raises an error" do
        expect { subject.to raise_error(NameError) }
      end
    end
  end

  describe ".pack_word" do
    it "packs argument as 16-bit unsigned" do
      expect(described_class.pack_word(0x4141)).to eq("AA")
    end

    it "truncates arguments longer than 16-bit unsigned" do
      expect(described_class.pack_word(0x41414242)).to eq("BB")
    end

    it "packs as little endian" do
      expect(described_class.pack_word(0x4142)).to eq("BA")
    end
  end

  describe ".pack_dword" do
    it "packs argument as 32-bit unsigned" do
      expect(described_class.pack_dword(0x41414141)).to eq("AAAA")
    end

    it "truncates arguments longer than 16-bit unsigned" do
      expect(described_class.pack_dword(0x4142424242)).to eq("BBBB")
    end

    it "packs as little endian" do
      expect(described_class.pack_dword(0x41424344)).to eq("DCBA")
    end
  end

  describe ".pack_lsb" do
    it "returns the least significant byte of a packed dword" do
      expect(described_class.pack_lsb(0x41424344)).to eq("D")
    end
  end

  describe ".pack_lsb" do
    it "returns the least significant byte of a packed dword" do
      expect(described_class.pack_lsb(0x41424344)).to eq("D")
    end
  end

  describe "._check_reg" do
    context "when single argument" do
      context "is valid" do
        it { expect(described_class._check_reg(Rex::Arch::X86::EDI)).to be_nil }
      end

      context "is invalid" do
        it { expect { described_class._check_reg(0xfffffff) }.to raise_error(Rex::ArgumentError) }
      end
    end

    context "when several arguments" do
      context "are valid" do
        it { expect(described_class._check_reg(Rex::Arch::X86::EDI, Rex::Arch::X86::ESI)).to be_nil }
      end

      context "include an invalid one" do
        it { expect { described_class._check_reg(Rex::Arch::X86::EDI, 0xfffffff) }.to raise_error(Rex::ArgumentError) }
      end
    end
  end

  describe "._check_badchars" do
    subject { described_class._check_badchars("Test", badchars) }

    context "when data contains badchars" do
      let(:badchars) { "sac" }

      it "raises an error" do
        expect { subject.to raise_error(Rex::RuntimeError) }
      end
    end

    context "when data doesn't contain badhars" do
      let(:badchars) { "dac" }
      it { is_expected.to eq("Test") }
    end
  end

  describe ".fpu_instructions" do
    subject { described_class.fpu_instructions }

    it "returns an Array" do
      is_expected.to be_an(Array)
    end

    it "includes valid FPU instructions" do
      is_expected.to include("\xd9\xd0")
      is_expected.to include("\xda\xc0")
    end
  end

  describe ".jmp_reg" do
    subject { described_class.jmp_reg(reg) }

    context "when valid register" do
      let(:reg) { "eax" }
      it { is_expected.to eq("\xFF\xE0") }
    end

    context "when invalid register" do
      let(:reg) { "non_existent"}
      it "raises an error" do
        expect{ subject.to raise_error(NameError) }
      end
    end
  end

  describe ".rel_number" do

    context "when no delta argument" do
      subject { described_class.rel_number(num) }

      context "num argument starts with $+" do
        let(:num) { "$+20" }
        it { is_expected.to eq(20)}
      end

      context "num argument is $+" do
        let(:num) { "$+" }
        it { is_expected.to eq(0)}
      end

      context "num argument starts with $-" do
        let(:num) { "$-20" }
        it { is_expected.to eq(-20)}
      end

      context "num argument is $-" do
        let(:num) { "$-" }
        it { is_expected.to eq(0)}
      end

      context "num argument starts with 0x" do
        let(:num) { "0x20" }
        it { is_expected.to eq(32)}
      end

      context "num argument is 0x" do
        let(:num) { "0x" }
        it { is_expected.to eq(0)}
      end

      context "num argument is other string" do
        let(:num) { "20" }
        it "raises error" do
          expect { subject.to raise_error(TypeError) }
        end
      end

      context "num argument is a number" do
        let(:num) { 20 }
        it { is_expected.to eq(20) }
      end
    end

    context "when there is delta argument" do
      subject { described_class.rel_number(num, delta) }
      let(:delta) { 20 }

      context "num argument starts with $+" do
        let(:num) { "$+20" }
        it { is_expected.to eq(40)}
      end

      context "num argument is $+" do
        let(:num) { "$+" }
        it { is_expected.to eq(20)}
      end

      context "num argument starts with $-" do
        let(:num) { "$-20" }
        it { is_expected.to eq(0)}
      end

      context "num argument is $-" do
        let(:num) { "$-" }
        it { is_expected.to eq(20)}
      end

      context "num argument starts with 0x" do
        let(:num) { "0x20" }
        it { is_expected.to eq(52)}
      end

      context "num argument is 0x" do
        let(:num) { "0x" }
        it { is_expected.to eq(20)}
      end

      context "num argument is other string" do
        let(:num) { "20" }
        it "raises error" do
          expect { subject.to raise_error(TypeError) }
        end
      end

      context "num argument is a number" do
        let(:num) { 20 }
        it { is_expected.to eq(20) }
      end
    end
  end

  describe ".loop" do
    subject { described_class.loop(offset) }

    context "offset argument is number" do
      context "1" do
        let(:offset) { 1 }
        it { is_expected.to eq("\xE2\x01") }
      end

      context "255" do
        let(:offset) { 255 }
        it { is_expected.to eq("\xE2\xFF") }
      end

      context "within half-word range" do
        let(:offset) { 65534 }
        it "truncates offset" do
          is_expected.to eq("\xE2\xFE")
        end
      end
    end

    context "offset argument is string" do
      context "starting with $+" do
        let(:offset) { "$+20" }
        it { is_expected.to eq("\xe2\x12") }
      end

      context "$+" do
        let(:offset) { "$+" }
        it { is_expected.to eq("\xe2\xfe") }
      end

      context "starting with $-" do
        let(:offset) { "$-20" }
        it { is_expected.to eq("\xe2\xea") }
      end

      context "$-" do
        let(:offset) { "$-" }
        it { is_expected.to eq("\xe2\xfe") }
      end

      context "starting with 0x" do
        let(:offset) { "0x20" }
        it { is_expected.to eq("\xe2\x1e") }
      end

      context "0x" do
        let(:offset) { "0x" }
        it { is_expected.to eq("\xe2\xfe") }
      end

      context "0x41ff" do
        let(:offset) { "0x41ff" }
        it "truncates offset" do
          is_expected.to eq("\xe2\xfd")
        end
      end

      context "starting in another way" do
        let(:offset) { "20" }
        it "raises error" do
          expect { subject.to raise_error(TypeError) }
        end
      end
    end
  end

  describe ".jmp" do
    subject { described_class.jmp(addr) }

    context "addr is number" do
      let(:addr) { 0x41424344 }
      it  { is_expected.to eq("\xE9\x44\x43\x42\x41") }
    end

    context "addr is string" do
      context "starting with $+" do
        let(:addr) { "$+200" }
        it { is_expected.to eq("\xe9\xc8\x00\x00\x00") }
      end

      context "$+" do
        let(:addr) { "$+" }
        it { is_expected.to eq("\xe9\x00\x00\x00\x00") }
      end

      context "starting with $-" do
        let(:addr) { "$-20" }
        it { is_expected.to eq("\xe9\xec\xff\xff\xff") }
      end

      context "$-" do
        let(:addr) { "$-" }
        it { is_expected.to eq("\xe9\x00\x00\x00\x00") }
      end

      context "starting with 0x" do
        let(:addr) { "0x41424344" }
        it { is_expected.to eq("\xe9\x44\x43\x42\x41") }
      end

      context "0x" do
        let(:addr) { "0x" }
        it { is_expected.to eq("\xe9\x00\x00\x00\x00") }
      end

      context "starting in another way" do
        let(:addr) { "20" }
        it "raises error" do
          expect { subject.to raise_error(TypeError) }
        end
      end
    end
  end

  describe ".dword_adjust" do

    context "when one byte string is sent as dword" do
      subject { described_class.dword_adjust(dword) }
      let(:dword) { "\xff"}

      it "raises error" do
        expect { subject.to raise_error(NoMethodError) }
      end
    end

    context "when amount argument isn't set" do
      subject { described_class.dword_adjust(dword) }
      let(:dword) { "\xff\xff\xff\xff"}

      it "returns the same dword packed" do
        is_expected.to eq("\xff\xff\xff\xff")
      end
    end

    context "when amount argument is set" do
      subject { described_class.dword_adjust(dword, amount) }

      context "and doesn't overflow" do
        let(:dword) { "\x41\x42\x43\x44" }
        let(:amount) { 2 }

        it "returns the incremented dword packed" do
          is_expected.to eq("\x43\x42\x43\x44")
        end
      end

      context "and overflows" do
        let(:dword) { "\xff\xff\xff\xff" }
        let(:amount) { 1 }

        it "raises error" do
          expect { subject.to raise_error(NoMethodError) }
        end
      end
    end
  end

  describe ".searcher" do
    subject { described_class.searcher(tag) }

    context "when tag is between '\\x00\\x00\\x00\\x00' and '\\xff\\xff\\xff\\xff'" do
      let(:signature) do
        "\x39\x37\x75\xfb\x46"
      end

      let(:tag) do
        [0x41424344].pack("V")
      end

      it "returns the searcher routine" do
        is_expected.to include(signature)
      end
    end

    context "when tag is '\\x00\\x00\\x00\\x00'" do
      let(:tag) do
        [0x00000000].pack("V")
      end

      let(:signature) do
        "\xbe\xff\xff\xff\xff"
      end

      it "initializes an underflowed esi" do
        is_expected.to include(signature)
      end
    end
  end

  describe ".push_dword" do
    subject { described_class.push_dword(val) }
    let(:val) { 0x41424344 }
    it "returns a push dword instruction" do
      is_expected.to eq("\x68\x44\x43\x42\x41")
    end
  end

  describe ".copy_to_stack" do
    subject { described_class.copy_to_stack(len) }

    context "when len argument is four byte aligned" do
      let(:len) { 4 }

      it "returns 'copy_to_stack' snippet" do
        is_expected.to include("\xeb\x0f\x68\x04\x00\x00\x00")
      end
    end

    context "when len argument isn't four byte aligned" do
      let(:len) { 3 }

      it "returns snippet with len aligned" do
        is_expected.to include("\xeb\x0f\x68\x04\x00\x00\x00")
      end
    end
  end

  describe ".jmp_short" do
    subject { described_class.jmp_short(addr) }

    context "when addr is number" do
      context "one byte length" do
        let(:addr) { 0x00 }
        it "returns the jmp instr to the addr" do
          is_expected.to eq("\xeb\x00")
        end
      end

      context "> one byte length" do
        let(:addr) { 0x4142 }


        it "returns the jmp instr to the addr truncated" do
          is_expected.to eq("\xeb\x42")
        end
      end
    end

    context "when addr is string" do
      context "starting with $+" do
        let(:addr) { "$+4" }
        it { is_expected.to eq("\xeb\x2") }
      end

      context "$+" do
        let(:addr) { "$+" }
        it { is_expected.to eq("\xeb\xfe") }
      end

      context "starting with $-" do
        let(:addr) { "$-2" }
        it { is_expected.to eq("\xeb\xfc") }
      end

      context "$-" do
        let(:addr) { "$-" }
        it { is_expected.to eq("\xeb\xfe") }
      end

      context "starting with 0x" do
        let(:addr) { "0x41" }
        it { is_expected.to eq("\xeb\x3f") }
      end

      context "0x" do
        let(:addr) { "0x" }
        it { is_expected.to eq("\xeb\xfe") }
      end

      context "with a two bytes number" do
        let(:addr) { "0x4142" }
        it "truncates" do
          is_expected.to eq("\xeb\x40")
        end
      end

      context "starting in another way" do
        let(:addr) { "20" }
        it "raises error" do
          expect { subject.to raise_error(TypeError) }
        end
      end
    end
  end

  describe ".call" do
    subject { described_class.call(addr) }

    context "addr is number" do
      let(:addr) { 0x41424344 }
      it  { is_expected.to eq("\xE8\x44\x43\x42\x41") }
    end

    context "addr is string" do
      context "starting with $+" do
        let(:addr) { "$+200" }
        it { is_expected.to eq("\xe8\xc3\x00\x00\x00") }
      end

      context "$+" do
        let(:addr) { "$+" }
        it { is_expected.to eq("\xe8\xfb\xff\xff\xff") }
      end

      context "starting with $-" do
        let(:addr) { "$-20" }
        it { is_expected.to eq("\xe8\xe7\xff\xff\xff") }
      end

      context "$-" do
        let(:addr) { "$-" }
        it { is_expected.to eq("\xe8\xfb\xff\xff\xff") }
      end

      context "starting with 0x" do
        let(:addr) { "0x41424344" }
        it { is_expected.to eq("\xe8\x3f\x43\x42\x41") }
      end

      context "0x" do
        let(:addr) { "0x" }
        it { is_expected.to eq("\xe8\xfb\xff\xff\xff") }
      end

      context "starting in another way" do
        let(:addr) { "20" }
        it "raises error" do
          expect { subject.to raise_error(TypeError) }
        end
      end
    end
  end

  describe ".reg_name32" do
    subject { described_class.reg_name32(num) }

    context "when reg id is valid" do
      let(:num) { rand(7) }
      it { is_expected.to be_an(String) }
    end

    context "when reg id isn't valid" do
      let(:num) { 29 }
      it "raises an error" do
        expect { subject.to raise_error(ArgumentError) }
      end
    end
  end

end
