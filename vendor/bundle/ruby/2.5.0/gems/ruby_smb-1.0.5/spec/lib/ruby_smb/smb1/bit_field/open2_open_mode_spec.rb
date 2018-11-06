RSpec.describe RubySMB::SMB1::BitField::Open2OpenMode do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :file_exists_opts }
  it { is_expected.to respond_to :create_file }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'file_exists_opts' do
    it 'should be a 2-bit field per the SMB spec' do
      expect(flags.file_exists_opts).to be_a BinData::Bit2
    end

    it_behaves_like 'bit field with one flag set', :file_exists_opts, 'v', 0x0001
  end

  describe 'create_file' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.create_file).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :create_file, 'v', 0x0010
  end
end
