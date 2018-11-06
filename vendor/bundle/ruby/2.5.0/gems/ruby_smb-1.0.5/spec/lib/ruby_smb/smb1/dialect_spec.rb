RSpec.describe RubySMB::SMB1::Dialect do
  subject(:dialect) { described_class.new }

  it { is_expected.to respond_to :buffer_format }
  it { is_expected.to respond_to :dialect_string }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'buffer_format' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(dialect.buffer_format).to be_a BinData::Bit8
    end

    it 'should be hardcoded to 0x2 by default per the SMB spec' do
      expect(dialect.buffer_format).to eq 0x2
    end
  end

  describe 'dialect_string' do
    it 'should be a null terminated string per the SMB spec' do
      expect(dialect.dialect_string).to be_a BinData::Stringz
    end
  end
end
