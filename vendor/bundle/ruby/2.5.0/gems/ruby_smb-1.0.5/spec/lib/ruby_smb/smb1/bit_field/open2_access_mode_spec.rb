RSpec.describe RubySMB::SMB1::BitField::Open2AccessMode do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :sharing_mode }
  it { is_expected.to respond_to :access_mode }
  it { is_expected.to respond_to :writethrough }
  it { is_expected.to respond_to :cache_mode }
  it { is_expected.to respond_to :reference_locality }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'access_mode' do
    it 'should be a 3-bit field per the SMB spec' do
      expect(flags.access_mode).to be_a BinData::Bit3
    end

    it_behaves_like 'bit field with one flag set', :access_mode, 'v', 0x0001
  end

  describe 'sharing_mode' do
    it 'should be a 3-bit field per the SMB spec' do
      expect(flags.sharing_mode).to be_a BinData::Bit3
    end

    it_behaves_like 'bit field with one flag set', :sharing_mode, 'v', 0x0010
  end

  describe 'reference_locality' do
    it 'should be a 3-bit field per the SMB spec' do
      expect(flags.reference_locality).to be_a BinData::Bit3
    end

    it_behaves_like 'bit field with one flag set', :reference_locality, 'v', 0x0100
  end

  describe 'cache_mode' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.cache_mode).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :cache_mode, 'v', 0x1000
  end

  describe 'writethrough' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.writethrough).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :writethrough, 'v', 0x4000
  end

  describe '#set_access_mode' do
    it 'sets access mode to 0 when given :r' do
      flags.set_access_mode :r
      expect(flags.access_mode).to eq 0
    end

    it 'sets access mode to 1 when given :w' do
      flags.set_access_mode :w
      expect(flags.access_mode).to eq 1
    end

    it 'sets access mode to 2 when given :rw' do
      flags.set_access_mode :rw
      expect(flags.access_mode).to eq 2
    end

    it 'sets access mode to 3 when given :x' do
      flags.set_access_mode :r
      expect(flags.access_mode).to eq 0
    end

    it 'raises an ArgumentError if given an invalid mode' do
      expect { flags.set_access_mode('abcd') }.to raise_error(ArgumentError)
    end
  end
end
