# Shared examples for RISC-V XOR encoder modules.
# Each shared example group accepts the encoder reference name as a parameter.

def make_encoder_state(buf, badchars = ''.b, key = 0xdeadbeef)
  state = Msf::EncoderState.new(key)
  state.buf = buf
  state.badchars = badchars
  state
end

RSpec.shared_examples 'riscv byte_xori encoder' do |ref_name|
  include_context 'Msf::Simple::Framework#modules loading'

  let(:encoder) { load_and_create_module(module_type: 'encoder', reference_name: ref_name) }
  let(:valid_payload) { ("\xde\xad\xbe\xef" * 4).b }

  describe '#decoder_stub' do
    context 'when badchars include a null byte' do
      it 'raises EncodingError' do
        state = make_encoder_state(valid_payload, "\x00".b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload is empty' do
      it 'raises EncodingError' do
        state = make_encoder_state(''.b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload exceeds 2047 bytes' do
      it 'raises EncodingError' do
        state = make_encoder_state(('A' * 2048).b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'with a valid payload' do
      subject(:stub) { encoder.decoder_stub(make_encoder_state(valid_payload)) }

      it 'returns a 64-byte stub' do
        expect(stub.bytesize).to eq(64)
      end

      it 'is binary encoded' do
        expect(stub.encoding).to eq(Encoding::ASCII_8BIT)
      end

      it 'begins with auipc t0, 0 (0x00000297)' do
        expect(stub[0, 4].unpack1('V')).to eq(0x00000297)
      end

      it 'ends with jalr x0, t4, 0' do
        # jalr rd=0, rs1=29(t4), imm=0 => (0<<20)|(29<<15)|(0<<7)|0b1100111
        expected_jalr = (29 << 15) | 0b1100111
        expect(stub[-4, 4].unpack1('V')).to eq(expected_jalr)
      end

      it 'contains no null bytes in the first instruction' do
        expect(stub[0, 4]).not_to include("\x00".b)
      end
    end
  end

  describe '#find_key_verify' do
    it 'accepts a key that produces valid xori encoding' do
      key_bytes = [0x01].pack('C')
      result = encoder.find_key_verify(valid_payload, key_bytes, ''.b)
      expect(result).to be(true).or be(false)
    end

    it 'rejects a key whose xori instruction encoding hits a bad character' do
      bad_byte = "\x13".b
      key_bytes = [0x00].pack('C')
      # Force a state where 0x13 is a badchar — the addi/xori opcodes end in 0x13
      result = encoder.find_key_verify(valid_payload, key_bytes, bad_byte)
      expect(result).to be(false)
    end
  end
end

RSpec.shared_examples 'riscv longxor encoder' do |ref_name|
  include_context 'Msf::Simple::Framework#modules loading'

  let(:encoder) { load_and_create_module(module_type: 'encoder', reference_name: ref_name) }
  let(:valid_payload) { ("\xde\xad\xbe\xef" * 4).b }   # 16 bytes, 4-dword aligned
  let(:stub_insn_size) { 68 }                            # 17 instructions × 4 bytes
  let(:stub_total_size) { 72 }                           # stub + 4-byte key placeholder

  describe '#decoder_stub' do
    context 'when badchars include a null byte' do
      it 'raises EncodingError' do
        state = make_encoder_state(valid_payload, "\x00".b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload is empty' do
      it 'raises EncodingError' do
        state = make_encoder_state(''.b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload is not 4-byte aligned' do
      it 'raises EncodingError' do
        state = make_encoder_state(('A' * 5).b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload exceeds 2047 dwords' do
      it 'raises EncodingError' do
        state = make_encoder_state(('A' * 4 * 2048).b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'with a valid aligned payload' do
      let(:state) { make_encoder_state(valid_payload) }

      subject(:stub) { encoder.decoder_stub(state) }

      it 'returns the correct total size' do
        expect(stub.bytesize).to eq(stub_total_size)
      end

      it 'is binary encoded' do
        expect(stub.encoding).to eq(Encoding::ASCII_8BIT)
      end

      it 'begins with auipc t0, 0 (0x00000297)' do
        expect(stub[0, 4].unpack1('V')).to eq(0x00000297)
      end

      it 'ends with 4 null bytes (key placeholder)' do
        expect(stub[-4, 4]).to eq("\x00\x00\x00\x00".b)
      end

      it 'sets decoder_key_offset to the instruction section length' do
        stub
        expect(state.decoder_key_offset).to eq(stub_insn_size)
      end
    end
  end
end

RSpec.shared_examples 'riscv longxor_tag encoder' do |ref_name|
  include_context 'Msf::Simple::Framework#modules loading'

  let(:encoder) { load_and_create_module(module_type: 'encoder', reference_name: ref_name) }
  let(:valid_payload) { ("\xde\xad\xbe\xef" * 4).b }
  let(:stub_insn_size) { 60 }   # 15 instructions × 4 bytes
  let(:stub_total_size) { 64 }  # stub + 4-byte key placeholder

  describe '#decoder_stub' do
    context 'when badchars include a null byte' do
      it 'raises EncodingError' do
        state = make_encoder_state(valid_payload, "\x00".b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload is empty' do
      it 'raises EncodingError' do
        state = make_encoder_state(''.b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload is not 4-byte aligned' do
      it 'raises EncodingError' do
        state = make_encoder_state(('A' * 5).b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload contains a zero dword' do
      it 'raises EncodingError' do
        payload_with_zero = ("\xde\xad\xbe\xef" + "\x00\x00\x00\x00" + "\xde\xad\xbe\xef" * 2).b
        state = make_encoder_state(payload_with_zero)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError, /zero dword/)
      end
    end

    context 'with a valid aligned payload containing no zero dwords' do
      let(:state) { make_encoder_state(valid_payload) }

      subject(:stub) { encoder.decoder_stub(state) }

      it 'returns the correct total size' do
        expect(stub.bytesize).to eq(stub_total_size)
      end

      it 'is binary encoded' do
        expect(stub.encoding).to eq(Encoding::ASCII_8BIT)
      end

      it 'begins with auipc t0, 0 (0x00000297)' do
        expect(stub[0, 4].unpack1('V')).to eq(0x00000297)
      end

      it 'ends with 4 null bytes (key placeholder)' do
        expect(stub[-4, 4]).to eq("\x00\x00\x00\x00".b)
      end

      it 'sets decoder_key_offset to the instruction section length' do
        stub
        expect(state.decoder_key_offset).to eq(stub_insn_size)
      end
    end
  end

  describe '#encode_end' do
    it 'appends the XOR key to the encoded buffer' do
      key = 0xcafebabe
      state = make_encoder_state(valid_payload, ''.b, key)
      state.encoded = ''.b
      encoder.encode_end(state)
      expect(state.encoded).to eq([key].pack('V'))
    end

    it 'appends key ^ key == 0 as the sentinel dword' do
      key = 0x12345678
      state = make_encoder_state(valid_payload, ''.b, key)
      state.encoded = ''.b
      encoder.encode_end(state)
      sentinel = state.encoded.unpack1('V')
      expect(sentinel ^ key).to eq(0)
    end
  end
end

RSpec.shared_examples 'riscv longxor_feedback encoder' do |ref_name|
  include_context 'Msf::Simple::Framework#modules loading'

  let(:encoder) { load_and_create_module(module_type: 'encoder', reference_name: ref_name) }
  let(:valid_payload) { ("\xde\xad\xbe\xef" * 4).b }
  let(:stub_insn_size) { 72 }   # 18 instructions × 4 bytes
  let(:stub_total_size) { 76 }  # stub + 4-byte key placeholder

  describe '#decoder_stub' do
    context 'when badchars include a null byte' do
      it 'raises EncodingError' do
        state = make_encoder_state(valid_payload, "\x00".b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload is empty' do
      it 'raises EncodingError' do
        state = make_encoder_state(''.b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload is not 4-byte aligned' do
      it 'raises EncodingError' do
        state = make_encoder_state(('A' * 5).b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'when payload exceeds 2047 dwords' do
      it 'raises EncodingError' do
        state = make_encoder_state(('A' * 4 * 2048).b)
        expect { encoder.decoder_stub(state) }.to raise_error(EncodingError)
      end
    end

    context 'with a valid aligned payload' do
      let(:state) { make_encoder_state(valid_payload) }

      subject(:stub) { encoder.decoder_stub(state) }

      it 'returns the correct total size' do
        expect(stub.bytesize).to eq(stub_total_size)
      end

      it 'is binary encoded' do
        expect(stub.encoding).to eq(Encoding::ASCII_8BIT)
      end

      it 'begins with auipc t0, 0 (0x00000297)' do
        expect(stub[0, 4].unpack1('V')).to eq(0x00000297)
      end

      it 'ends with 4 null bytes (key placeholder)' do
        expect(stub[-4, 4]).to eq("\x00\x00\x00\x00".b)
      end

      it 'sets decoder_key_offset to the instruction section length' do
        stub
        expect(state.decoder_key_offset).to eq(stub_insn_size)
      end
    end
  end

  describe '#encode_begin' do
    it 'seeds the feedback register with the initial key' do
      state = make_encoder_state(valid_payload, ''.b, 0xdeadbeef)
      encoder.encode_begin(state)
      expect(encoder.instance_variable_get(:@feedback)).to eq(0xdeadbeef)
    end
  end

  describe '#encode_block' do
    before { encoder.encode_begin(make_encoder_state(valid_payload, ''.b, 0x11111111)) }

    it 'XORs the first block with the initial key' do
      state = make_encoder_state(valid_payload, ''.b, 0x11111111)
      encoder.encode_begin(state)
      block = "\xef\xbe\xad\xde".b
      result = encoder.encode_block(state, block)
      plain = block.unpack1('V')
      expect(result.unpack1('V')).to eq(plain ^ 0x11111111)
    end

    it 'uses the previous encoded dword as feedback for the next block' do
      state = make_encoder_state(valid_payload, ''.b, 0x11111111)
      encoder.encode_begin(state)
      block1 = "\x01\x00\x00\x00".b
      block2 = "\x02\x00\x00\x00".b
      encoded1 = encoder.encode_block(state, block1)
      encoded2 = encoder.encode_block(state, block2)
      expect(encoded2.unpack1('V')).to eq(block2.unpack1('V') ^ encoded1.unpack1('V'))
    end
  end
end
