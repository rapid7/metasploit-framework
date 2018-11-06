RSpec.describe RubySMB::SMB1::BitField::OptionalSupport do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :search }
  it { is_expected.to respond_to :dfs }
  it { is_expected.to respond_to :csc_mask }
  it { is_expected.to respond_to :unique_filename }
  it { is_expected.to respond_to :extended_signature }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#search' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.search).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :search, 'v', 0x0001
  end

  describe '#dfs' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.dfs).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :dfs, 'v', 0x0002
  end

  describe '#csc_mask' do
    it 'should be a 2-bit field per the SMB spec' do
      expect(flags.csc_mask).to be_a BinData::Bit2
    end
  end

  describe '#unique_filename' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.unique_filename).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :unique_filename, 'v', 0x0010
  end

  describe '#extended_signature' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.extended_signature).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :extended_signature, 'v', 0x0020
  end
end
