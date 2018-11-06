RSpec.describe RubySMB::Nbss::SessionHeader do
  subject(:session_header) { described_class.new }

  it { is_expected.to respond_to :session_packet_type }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :packet_length }

  it 'is big endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  describe '#session_packet_type' do
    it 'is a 8-bit Unsigned Integer' do
      expect(session_header.session_packet_type).to be_a BinData::Uint8
    end
  end

  describe '#flags' do
    it 'is a 7-bit Unsigned Integer' do
      expect(session_header.flags).to be_a BinData::Bit7
    end
  end

  describe '#packet_length' do
    it 'is a 17-bit Unsigned Integer' do
      expect(session_header.packet_length).to be_a BinData::Bit17
    end
  end
end

