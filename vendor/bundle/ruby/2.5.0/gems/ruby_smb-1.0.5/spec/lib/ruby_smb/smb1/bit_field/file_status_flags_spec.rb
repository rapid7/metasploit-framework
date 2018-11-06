RSpec.describe RubySMB::SMB1::BitField::FileStatusFlags do
  subject(:options) { described_class.new }

  it { is_expected.to respond_to :reparse_tag }
  it { is_expected.to respond_to :no_substreams }
  it { is_expected.to respond_to :no_eas }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#reparse_tag' do
    it 'is a 1-bit flag' do
      expect(options.reparse_tag).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :reparse_tag, 'v', 0x0004
  end

  describe '#no_substreams' do
    it 'is a 1-bit flag' do
      expect(options.no_substreams).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :no_substreams, 'v', 0x0002
  end

  describe '#no_eas' do
    it 'is a 1-bit flag' do
      expect(options.no_eas).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :no_eas, 'v', 0x0001
  end
end
