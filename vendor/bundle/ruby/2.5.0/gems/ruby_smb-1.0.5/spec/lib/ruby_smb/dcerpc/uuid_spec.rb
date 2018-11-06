RSpec.describe RubySMB::Dcerpc::Uuid do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :time_low }
  it { is_expected.to respond_to :time_mid }
  it { is_expected.to respond_to :time_hi_and_version }
  it { is_expected.to respond_to :clock_seq_hi_and_reserved }
  it { is_expected.to respond_to :clock_seq_low }
  it { is_expected.to respond_to :node }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#time_low' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.time_low).to be_a BinData::Uint32le
    end
  end

  describe '#time_mid' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.time_mid).to be_a BinData::Uint16le
    end
  end

  describe '#time_hi_and_version' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.time_hi_and_version).to be_a BinData::Uint16le
    end
  end

  describe '#clock_seq_hi_and_reserved' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.clock_seq_hi_and_reserved).to be_a BinData::Uint8
    end
  end

  describe '#clock_seq_low' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.clock_seq_low).to be_a BinData::Uint8
    end
  end

  describe '#node' do
    it 'should be an Array' do
      expect(packet.node).to be_a BinData::Array
    end

    it 'should have 6 elements' do
      expect(packet.node.size).to eq 6
    end

    it 'should have 8-bit unsigned integer elements' do
      expect(packet.node[0]).to be_a BinData::Uint8
    end
  end

  context 'when using a string representation of UUID' do
    let(:uuid_string){ '8a885d04-1ceb-11c9-9fe8-08002b104860' }

    before :example do
      packet.set(uuid_string)
    end

    describe '#get' do
      it 'returns the correct string representation of UUID' do
        expect(packet.get).to eq uuid_string
      end
    end

    describe '#set' do
      it 'sets the expected values' do
        expect(packet.time_low).to eq 0x8A885D04
        expect(packet.time_mid).to eq 0x1CEb
        expect(packet.time_hi_and_version).to eq 0x11C9
        expect(packet.clock_seq_hi_and_reserved).to eq 0x9F
        expect(packet.clock_seq_low).to eq 0xE8
        expect(packet.node).to eq [0x08, 0x00, 0x2B, 0x10, 0x48, 0x60]
      end
    end
  end

end














RSpec.describe RubySMB::Dcerpc::Uuid do
  let(:uuid_string){'8a885d04-1ceb-11c9-9fe8-08002b104860'}
  let(:uuid){RubySMB::Dcerpc::Uuid.new(initial_value: uuid_string)}

  describe '#initialize' do
    it 'should create a 16 byte struct' do
      expect(uuid.do_num_bytes).to be 16
    end
  end
end
