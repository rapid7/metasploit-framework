RSpec.describe RubySMB::SMB1::BitField::SecurityFlags do
  subject(:options) { described_class.new }

  it { is_expected.to respond_to :effective_only }
  it { is_expected.to respond_to :context_tracking }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#effective_only' do
    it 'is a 1-bit flag' do
      expect(options.effective_only).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :effective_only, 'C', 0x02
  end

  describe '#context_tracking' do
    it 'is a 1-bit flag' do
      expect(options.context_tracking).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :context_tracking, 'C', 0x01
  end
end
