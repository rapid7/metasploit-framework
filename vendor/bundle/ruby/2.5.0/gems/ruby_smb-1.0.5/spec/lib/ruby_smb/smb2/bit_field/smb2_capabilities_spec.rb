RSpec.describe RubySMB::SMB2::BitField::Smb2Capabilities do
  subject(:capabilities) { described_class.new }

  it { is_expected.to respond_to :reserved2 }
  it { is_expected.to respond_to :encryption }
  it { is_expected.to respond_to :directory_leasing }
  it { is_expected.to respond_to :persistent_handles }
  it { is_expected.to respond_to :multi_channel }
  it { is_expected.to respond_to :large_mtu }
  it { is_expected.to respond_to :leasing }
  it { is_expected.to respond_to :dfs }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#encryption' do
    it 'is a 1-bit flag' do
      expect(capabilities.encryption).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :encryption, 'V', 0x00000040
  end

  describe '#directory_leasing' do
    it 'is a 1-bit flag' do
      expect(capabilities.directory_leasing).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :directory_leasing, 'V', 0x00000020
  end

  describe '#persistent_handles' do
    it 'is a 1-bit flag' do
      expect(capabilities.persistent_handles).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :persistent_handles, 'V', 0x00000010
  end

  describe '#multi_channel' do
    it 'is a 1-bit flag' do
      expect(capabilities.multi_channel).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :multi_channel, 'V', 0x00000008
  end

  describe '#large_mtu' do
    it 'is a 1-bit flag' do
      expect(capabilities.large_mtu).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :large_mtu, 'V', 0x00000004
  end

  describe '#leasing' do
    it 'is a 1-bit flag' do
      expect(capabilities.leasing).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :leasing, 'V', 0x00000002
  end

  describe '#dfs' do
    it 'is a 1-bit flag' do
      expect(capabilities.dfs).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :dfs, 'V', 0x00000001
  end
end
