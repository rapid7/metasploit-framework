RSpec.describe RubySMB::SMB1::BitField::TransFlags do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :no_response }
  it { is_expected.to respond_to :disconnect }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#no_response' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.no_response).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :no_response, 'C', 0x02
  end

  describe '#disconnect' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.disconnect).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :disconnect, 'C', 0x01
  end
end
