RSpec.describe RubySMB::SMB2::BitField::ShareCapabilities do
  subject(:capabilities) { described_class.new }

  it { is_expected.to respond_to :asymmetric }
  it { is_expected.to respond_to :cluster }
  it { is_expected.to respond_to :scaleout }
  it { is_expected.to respond_to :continuous }
  it { is_expected.to respond_to :dfs }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#dfs' do
    it 'is a 1-bit flag' do
      expect(capabilities.dfs).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :dfs, 'V', 0x00000008
  end

  describe '#continuous' do
    it 'is a 1-bit flag' do
      expect(capabilities.continuous).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :continuous, 'V', 0x00000010
  end

  describe '#scaleout' do
    it 'is a 1-bit flag' do
      expect(capabilities.scaleout).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :scaleout, 'V', 0x00000020
  end

  describe '#cluster' do
    it 'is a 1-bit flag' do
      expect(capabilities.cluster).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :cluster, 'V', 0x00000040
  end

  describe '#asymmetric' do
    it 'is a 1-bit flag' do
      expect(capabilities.asymmetric).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :asymmetric, 'V', 0x00000080
  end
end
