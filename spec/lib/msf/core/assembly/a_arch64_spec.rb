require 'spec_helper'
require 'msf/core/assembly/a_arch64'

RSpec.describe Msf::Assembly::AArch64 do
  describe '.instruction' do
    it 'selects and encodes the requested Metasm opcode' do
      expect(described_class.instruction('mov', rt: 0, rm: 31)).to eq("\xe0\x03\x1f\xaa".b)
      expect(described_class.instruction('svc', i16_5: 0)).to eq("\x01\x00\x00\xd4".b)
    end
  end

  describe '.branch' do
    it 'encodes a signed PC-relative displacement' do
      expect(described_class.branch('blt', instruction_address: 28, destination: 44)).to eq("\x8b\x00\x00\x54".b)
      expect(described_class.branch('b', instruction_address: 40, destination: 84, bits: 26, field: :i26_0)).to eq("\x0b\x00\x00\x14".b)
    end

    it 'rejects an unaligned destination' do
      expect do
        described_class.branch('b', instruction_address: 0, destination: 2, bits: 26, field: :i26_0)
      end.to raise_error(RangeError, 'AArch64 branch destination is not instruction-aligned')
    end
  end

  describe '.adr' do
    it 'encodes a signed PC-relative address' do
      expect(described_class.adr(instruction_address: 0, destination: 56, register: 1)).to eq("\xc1\x01\x00\x10".b)
      expect(described_class.adr(instruction_address: 4, destination: 0, register: 1)).to eq("\xe1\xff\xff\x10".b)
    end
  end
end
