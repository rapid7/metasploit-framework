RSpec.describe RubySMB::SMB1::BitField::Open2Flags do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :req_easize }
  it { is_expected.to respond_to :req_opbatch }
  it { is_expected.to respond_to :req_oplock }
  it { is_expected.to respond_to :req_attrib }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'req_attrib' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.req_attrib).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(flags.req_attrib).to eq 1
    end

    it_behaves_like 'bit field with one flag set', :req_attrib, 'v', 0x0001
  end

  describe 'req_oplock' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.req_oplock).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags.req_oplock).to eq 0
    end

    it_behaves_like 'bit field with one flag set', :req_oplock, 'v', 0x0002
  end

  describe 'req_opbatch' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.req_opbatch).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags.req_opbatch).to eq 0
    end

    it_behaves_like 'bit field with one flag set', :req_opbatch, 'v', 0x0004
  end

  describe 'req_easize' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.req_easize).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(flags.req_easize).to eq 1
    end

    it_behaves_like 'bit field with one flag set', :req_easize, 'v', 0x0008
  end
end
