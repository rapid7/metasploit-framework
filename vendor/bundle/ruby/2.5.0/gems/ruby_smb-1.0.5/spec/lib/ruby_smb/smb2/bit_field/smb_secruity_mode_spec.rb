RSpec.describe RubySMB::SMB2::BitField::Smb2SecurityMode do
  subject(:security_mode) { described_class.new }

  it { is_expected.to respond_to :signing_required }
  it { is_expected.to respond_to :signing_enabled }

  describe '#signing_required' do
    it 'is a 1-bit flag' do
      expect(security_mode.signing_required).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :signing_required, 'v', 0x0002
  end

  describe '#signing_enabled' do
    it 'is a 1-bit flag' do
      expect(security_mode.signing_enabled).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :signing_enabled, 'v', 0x0001
  end
end
