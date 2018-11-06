RSpec.describe RubySMB::SMB1::BitField::ShareAccess do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :share_delete }
  it { is_expected.to respond_to :share_write }
  it { is_expected.to respond_to :share_read }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#share_read' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.share_read).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :share_read, 'V', 0x00000001
  end

  describe '#share_write' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.share_write).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :share_write, 'V', 0x00000002
  end

  describe '#share_delete' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.share_delete).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :share_delete, 'V', 0x00000004
  end
end
