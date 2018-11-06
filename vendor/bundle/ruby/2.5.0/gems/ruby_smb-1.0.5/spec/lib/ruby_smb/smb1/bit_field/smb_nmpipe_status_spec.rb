RSpec.describe RubySMB::SMB1::BitField::SmbNmpipeStatus do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :icount }
  it { is_expected.to respond_to :nonblocking }
  it { is_expected.to respond_to :endpoint }
  it { is_expected.to respond_to :nmpipe_type }
  it { is_expected.to respond_to :read_mode }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'icount' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(flags.icount).to be_a BinData::Bit8
    end
  end

  describe 'read_mode' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.read_mode).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :read_mode, 'v', 0x0100
  end

  describe 'nmpipe_type' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.nmpipe_type).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :nmpipe_type, 'v', 0x0400
  end

  describe 'endpoint' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.endpoint).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :endpoint, 'v', 0x4000
  end

  describe 'nonblocking' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.nonblocking).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :nonblocking, 'v', 0x8000
  end
end
