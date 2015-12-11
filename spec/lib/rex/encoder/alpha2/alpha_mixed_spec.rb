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

    context "when modified_registers is passed" do
      context "when reg is ECX" do
        context "when offset is 10" do
          let(:reg) { 'ECX' }
          let(:offset) { 10 }
          let(:modified_registers) { [] }

          it "marks ECX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::ECX)
          end

          it "marks EBX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EBX)
          end

          it "marks EDX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EDX)
          end
        end

        context "when offset is 5" do
          let(:reg) { 'ECX' }
          let(:offset) { 5 }
          let(:modified_registers) { [] }

          it "marks ECX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::ECX)
          end

          it "marks EBX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EBX)
          end

          it "marks EDX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EDX)
          end
        end

        context "when offset is 0" do
          let(:reg) { 'ECX' }
          let(:offset) { 0 }
          let(:modified_registers) { [] }

          it "marks ECX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::ECX)
          end

          it "doesn't mark EBX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to_not include(Rex::Arch::X86::EBX)
          end

          it "marks EDX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EDX)
          end
        end

        context "when offset is 15" do
          let(:reg) { 'ECX' }
          let(:offset) { 15 }
          let(:modified_registers) { [] }

          it "marks ECX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::ECX)
          end

          it "marks EBX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EBX)
          end

          it "marks EDX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EDX)
          end
        end
      end

      context "when reg is EDX" do
        context "when offset is 10" do
          let(:reg) { 'EDX' }
          let(:offset) { 10 }
          let(:modified_registers) { [] }

          it "marks ECX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::ECX)
          end

          it "marks EBX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EBX)
          end

          it "marks EDX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EDX)
          end
        end

        context "when offset is 5" do
          let(:reg) { 'EDX' }
          let(:offset) { 5 }
          let(:modified_registers) { [] }

          it "marks ECX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::ECX)
          end

          it "marks EBX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EBX)
          end

          it "marks EDX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EDX)
          end
        end

        context "when offset is 0" do
          let(:reg) { 'EDX' }
          let(:offset) { 0 }
          let(:modified_registers) { [] }

          it "marks ECX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::ECX)
          end

          it "doesn't mark EBX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to_not include(Rex::Arch::X86::EBX)
          end

          it "marks EDX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EDX)
          end
        end

        context "when offset is 15" do
          let(:reg) { 'EDX' }
          let(:offset) { 15 }
          let(:modified_registers) { [] }

          it "marks ECX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::ECX)
          end

          it "marks EBX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EBX)
          end

          it "marks EDX as modified" do
            described_class.gen_decoder_prefix(reg, offset, modified_registers)
            expect(modified_registers).to include(Rex::Arch::X86::EDX)
          end
        end
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

    context "when modified_registers passed" do
      let(:modified_registers) { [] }
      it "marks EDX as modified" do
        described_class.gen_decoder(reg, offset, modified_registers)
        expect(modified_registers).to include(Rex::Arch::X86::EDX)
      end

      it "marks ECX as modified" do
        described_class.gen_decoder(reg, offset, modified_registers)
        expect(modified_registers).to include(Rex::Arch::X86::ECX)
      end

      it "marks EAX as modified" do
        described_class.gen_decoder(reg, offset, modified_registers)
        expect(modified_registers).to include(Rex::Arch::X86::EAX)
      end

      it "marks ESP as modified" do
        described_class.gen_decoder(reg, offset, modified_registers)
        expect(modified_registers).to include(Rex::Arch::X86::ESP)
      end
    end
  end
end
