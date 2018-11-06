RSpec.describe RubySMB::Nbss::SessionRequest do
  subject(:session_request) { described_class.new }

  it { is_expected.to respond_to :session_header }
  it { is_expected.to respond_to :called_name }
  it { is_expected.to respond_to :calling_name }

  it 'is big endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  describe '#session_header' do
    it 'is a SessionHeader field' do
      expect(session_request.session_header).to be_a RubySMB::Nbss::SessionHeader
    end
  end

  describe '#called_name' do
    it 'is a string' do
      expect(session_request.called_name).to be_a RubySMB::Nbss::NetbiosName
    end
  end

  describe '#calling_name' do
    it 'is a string' do
      expect(session_request.calling_name).to be_a RubySMB::Nbss::NetbiosName
    end
  end
end

