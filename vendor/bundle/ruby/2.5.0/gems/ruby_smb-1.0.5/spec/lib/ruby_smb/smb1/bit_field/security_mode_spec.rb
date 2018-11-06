RSpec.describe RubySMB::SMB1::BitField::SecurityMode do
  subject(:security_mode) { described_class.new }

  it { is_expected.to respond_to :user_security }
  it { is_expected.to respond_to :encrypt_passwords }
  it { is_expected.to respond_to :security_signatures_enabled }
  it { is_expected.to respond_to :security_signatures_required }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#user_security' do
    it 'is a 1-bit flag' do
      expect(security_mode.user_security).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :user_security, 'C', 0x01
  end

  describe '#encrypt_passwords' do
    it 'is a 1-bit flag' do
      expect(security_mode.encrypt_passwords).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :encrypt_passwords, 'C', 0x02
  end

  describe '#security_signatures_enabled' do
    it 'is a 1-bit flag' do
      expect(security_mode.security_signatures_enabled).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :security_signatures_enabled, 'C', 0x04
  end

  describe '#security_signatures_required' do
    it 'is a 1-bit flag' do
      expect(security_mode.security_signatures_required).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :security_signatures_required, 'C', 0x08
  end
end
