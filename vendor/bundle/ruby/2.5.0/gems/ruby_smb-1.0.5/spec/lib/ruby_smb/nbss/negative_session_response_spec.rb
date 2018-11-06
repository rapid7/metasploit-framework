RSpec.describe RubySMB::Nbss::NegativeSessionResponse do
  subject(:negative_session_response) { described_class.new }

  it { is_expected.to respond_to :session_header }
  it { is_expected.to respond_to :error_code }

  it 'is big endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  describe '#session_header' do
    it 'is a SessionHeader field' do
      expect(negative_session_response.session_header).to be_a RubySMB::Nbss::SessionHeader
    end
  end

  describe '#error_code' do
    it 'is a 8-bit Unsigned Integer' do
      expect(negative_session_response.error_code).to be_a BinData::Uint8
    end
  end

  describe '#error_msg' do
    it 'returns a string describing the error' do
      negative_session_response.error_code = 0x80
      expect(negative_session_response.error_msg).to eq 'Not listening on called name'
    end
  end
end
