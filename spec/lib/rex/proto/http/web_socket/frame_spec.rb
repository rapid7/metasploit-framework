RSpec.describe Rex::Proto::Http::WebSocket::Frame do
  subject(:frame) { Rex::Proto::Http::WebSocket::Frame.new }

  it { is_expected.to respond_to :header }
  it { is_expected.to respond_to :payload_data }
  it { is_expected.to respond_to :payload_len }

  describe '#apply_masking_key' do
    it 'returns an empty string when given an empty string' do
      expect(described_class.apply_masking_key('', rand(1..0xffffffff))).to eq ''
    end

    it 'properly applies the XOR algorithm as described by the RFC' do
      # example taken from https://datatracker.ietf.org/doc/html/rfc6455#section-5.7
      masking_key = [ 0x37, 0xfa, 0x21, 0x3d ].pack('C*').unpack1('N')
      ciphertext = [ 0x7f, 0x9f, 0x4d, 0x51, 0x58 ].pack('C*')
      expect(described_class.apply_masking_key(ciphertext, masking_key)).to eq 'Hello'
    end
  end

  describe '#initialize' do
    it 'should set the fin flag by default' do
      expect(described_class.new.header.fin).to eq 1
    end
  end

  describe '#from_binary' do
    let(:payload) { Random.new.bytes(rand(10..20)) }
    let(:binary_frame) { described_class.from_binary(payload) }

    it 'has the correct opcode' do
      expect(binary_frame.header.opcode).to eq Rex::Proto::Http::WebSocket::Opcode::BINARY
    end

    it 'has the correct payload' do
      expect(binary_frame.payload_len).to eq payload.length
      expect(binary_frame.payload_data).to eq described_class.apply_masking_key(payload, binary_frame.header.masking_key)
    end

    it 'is the last fragment frame' do
      expect(binary_frame.header.fin).to eq 1
    end
  end

  describe '#from_text' do
    let(:payload) { Faker::Alphanumeric.alpha(number: rand(10..20)) }
    let(:text_frame) { described_class.from_text(payload) }

    it 'has the correct opcode' do
      expect(text_frame.header.opcode).to eq Rex::Proto::Http::WebSocket::Opcode::TEXT
    end

    it 'has the correct payload' do
      expect(text_frame.payload_len).to eq payload.length
      expect(text_frame.payload_data).to eq described_class.apply_masking_key(payload, text_frame.header.masking_key)
    end

    it 'is the last fragment frame' do
      expect(text_frame.header.fin).to eq 1
    end
  end

  describe '#mask!' do
    let(:plaintext) { Faker::Alphanumeric.alpha(number: rand(10..20)) }

    before(:each) do
      frame.header.masked = 0
      frame.payload_data = plaintext
    end

    it 'should return the masked payload' do
      retval = frame.mask!
      expect(retval).to be_a String
      expect(retval).to_not eq plaintext
      expect(retval.length).to eq plaintext.length
    end

    it 'should accept an explicit masking key' do
      retval = frame.mask!(0)
      expect(retval).to be_a String
      expect(retval).to eq plaintext
    end

    context 'after called' do
      before(:each) do
        frame.header.masked = 0
        frame.payload_data = plaintext
        frame.mask!
      end

      it 'the masking key should be set' do
        expect(frame.header.masking_key.value).to be_a Integer
      end

      it 'the masked bit should be set' do
        expect(frame.header.masked).to eq 1
      end

      it 'the payload should be different' do
        expect(frame.payload_data).to_not eq plaintext
      end
    end
  end

  describe '#unmask!' do
    let(:masking_key) { rand(1..0xffffffff) }
    let(:plaintext) { Faker::Alphanumeric.alpha(number: rand(10..20)) }
    let(:ciphertext) { described_class.apply_masking_key(plaintext, masking_key) }

    before(:each) do
      frame.header.masked = 1
      frame.header.masking_key = masking_key
      frame.payload_data = ciphertext
    end

    it 'should return the unmasked payload' do
      retval = frame.unmask!
      expect(retval).to eq plaintext
    end

    context 'after called' do
      before(:each) do
        frame.header.masked = 1
        frame.header.masking_key = masking_key
        frame.payload_data = ciphertext
        frame.unmask!
      end

      it 'the masked bit should be clear' do
        expect(frame.header.masked).to eq 0
      end

      it 'the payload should be different' do
        expect(frame.payload_data).to eq plaintext
      end
    end
  end
end
