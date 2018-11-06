RSpec.describe RubySMB::SMB1::BitField::SmbFileAttributes do
  subject(:attrs) { described_class.new }

  it { is_expected.to respond_to :archive }
  it { is_expected.to respond_to :directory }
  it { is_expected.to respond_to :volume }
  it { is_expected.to respond_to :system }
  it { is_expected.to respond_to :hidden }
  it { is_expected.to respond_to :read_only }
  it { is_expected.to respond_to :search_archive }
  it { is_expected.to respond_to :search_directory }
  it { is_expected.to respond_to :search_system }
  it { is_expected.to respond_to :search_hidden }
  it { is_expected.to respond_to :search_read_only }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'read_only' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.read_only).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :read_only, 'v', 0x0001
  end

  describe 'hidden' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.hidden).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :hidden, 'v', 0x0002
  end

  describe 'system' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.system).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :system, 'v', 0x0004
  end

  describe 'volume' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.volume).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :volume, 'v', 0x0008
  end

  describe 'directory' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.directory).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :directory, 'v', 0x0010
  end

  describe 'archive' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.archive).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :archive, 'v', 0x0020
  end

  describe 'search_read_only' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.search_read_only).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :search_read_only, 'v', 0x0100
  end

  describe 'search_hidden' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.search_hidden).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :search_hidden, 'v', 0x0200
  end

  describe 'search_system' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.search_system).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :search_system, 'v', 0x0400
  end

  describe 'search_directory' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.search_directory).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :search_directory, 'v', 0x1000
  end

  describe 'search_archive' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.search_archive).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :search_archive, 'v', 0x2000
  end
end
