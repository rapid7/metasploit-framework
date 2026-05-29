require 'spec_helper'

RSpec.describe 'modules/payloads/singles/linux/riscv32le/shell_reverse_tcp' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'linux/riscv32le/shell_reverse_tcp',
      ancestor_reference_names: ['singles/linux/riscv32le/shell_reverse_tcp']
    )
  end

  before(:each) do
    subject.datastore.merge!('LHOST' => '192.0.2.1', 'LPORT' => '4444')
  end

  describe '#generate' do
    it 'returns a non-empty binary string' do
      expect(subject.generate).not_to be_empty
    end

    it 'generates a payload matching CachedSize' do
      # described_class is nil for string-described examples; use subject.class
      expect(subject.generate.bytesize).to eq(subject.class::CachedSize)
    end

    it 'encodes LHOST in the shellcode' do
      raw_default = subject.generate
      subject.datastore['LHOST'] = '192.0.2.2'
      raw_other = subject.generate
      # LHOST is embedded in LUI/ADDI instruction words, not as raw bytes,
      # so verify that a different LHOST produces different shellcode.
      expect(raw_default).not_to eq(raw_other)
    end

    it 'encodes LPORT in the shellcode' do
      raw_default = subject.generate
      subject.datastore['LPORT'] = '9999'
      raw_other = subject.generate
      expect(raw_default).not_to eq(raw_other)
    end

    it 'sets up argv[0] pointing to the path (not NULL) for BusyBox compatibility' do
      raw = subject.generate
      # sw sp,8(sp)   — stores &path as argv[0]
      expect(raw).to include([0x00212423].pack('V'))
      # sw zero,12(sp) — NULL-terminates argv[]
      expect(raw).to include([0x00012623].pack('V'))
      # addi a1,sp,8  — a1 = argv
      expect(raw).to include([0x00810593].pack('V'))
    end

    it 'does not pass NULL as argv to execve' do
      raw = subject.generate
      # li a1,0; li a2,0; ecall — the unfixed null-argv sequence
      null_argv_sequence = [0x00000593, 0x00000613, 0x00000073].pack('V*')
      expect(raw).not_to include(null_argv_sequence)
    end
  end
end
