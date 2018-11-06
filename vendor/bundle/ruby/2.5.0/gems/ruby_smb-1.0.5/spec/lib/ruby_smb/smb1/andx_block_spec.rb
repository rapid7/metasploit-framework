RSpec.describe RubySMB::SMB1::AndXBlock do
  subject(:andx_block) { described_class.new }

  it { is_expected.to respond_to :andx_command }
  it { is_expected.to respond_to :andx_reserved }
  it { is_expected.to respond_to :andx_offset }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'andx_command' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(andx_block.andx_command).to be_a BinData::Bit8
    end

    it 'should be hardcoded to SMB_COM_NO_ANDX_COMMAND by default per the SMB spec' do
      expect(andx_block.andx_command).to eq RubySMB::SMB1::Commands::SMB_COM_NO_ANDX_COMMAND
    end
  end

  describe 'andx_reserved' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(andx_block.andx_reserved).to be_a BinData::Bit8
    end

    it 'should be hardcoded to 0 by default per the SMB spec' do
      expect(andx_block.andx_reserved).to eq 0
    end
  end

  describe 'andx_offset' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(andx_block.andx_offset).to be_a BinData::Bit16
    end

    it 'should be hardcoded to 0 by default per the SMB spec' do
      expect(andx_block.andx_offset).to eq 0
    end
  end
end
