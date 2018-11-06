RSpec.describe RubySMB::SMB1::BitField::TreeConnectFlags do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :extended_response }
  it { is_expected.to respond_to :extended_signature }
  it { is_expected.to respond_to :disconnect }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#extended_response' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.extended_response).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :extended_response, 'C', 0x08
  end

  describe '#extended_signature' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.extended_signature).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :extended_signature, 'C', 0x04
  end

  describe '#disconnect' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.disconnect).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :disconnect, 'C', 0x01
  end
end
