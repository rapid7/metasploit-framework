RSpec.describe RubySMB::SMB1::BitField::Capabilities do
  subject(:capabilities) { described_class.new }

  it { is_expected.to respond_to :level_2_oplocks }
  it { is_expected.to respond_to :nt_status }
  it { is_expected.to respond_to :rpc_remote_apis }
  it { is_expected.to respond_to :nt_smbs }
  it { is_expected.to respond_to :large_files }
  it { is_expected.to respond_to :unicode }
  it { is_expected.to respond_to :mpx_mode }
  it { is_expected.to respond_to :raw_mode }
  it { is_expected.to respond_to :large_writex }
  it { is_expected.to respond_to :large_readx }
  it { is_expected.to respond_to :info_level_passthru }
  it { is_expected.to respond_to :dfs }
  it { is_expected.to respond_to :reserved1 }
  it { is_expected.to respond_to :bulk_transfer }
  it { is_expected.to respond_to :nt_find }
  it { is_expected.to respond_to :lock_and_read }
  it { is_expected.to respond_to :unix }
  it { is_expected.to respond_to :reserved2 }
  it { is_expected.to respond_to :lwio }
  it { is_expected.to respond_to :extended_security }
  it { is_expected.to respond_to :reserved3 }
  it { is_expected.to respond_to :dynamic_reauth }
  it { is_expected.to respond_to :reserved4 }
  it { is_expected.to respond_to :compressed_data }
  it { is_expected.to respond_to :reserved5 }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#level_2_oplocks' do
    it 'is a 1-bit flag' do
      expect(capabilities.level_2_oplocks).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :level_2_oplocks, 'V', 0x00000080
  end

  describe '#nt_status' do
    it 'is a 1-bit flag' do
      expect(capabilities.nt_status).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :nt_status, 'V', 0x00000040
  end

  describe '#rpc_remote_apis' do
    it 'is a 1-bit flag' do
      expect(capabilities.rpc_remote_apis).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :rpc_remote_apis, 'V', 0x00000020
  end

  describe '#nt_smbs' do
    it 'is a 1-bit flag' do
      expect(capabilities.nt_smbs).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :nt_smbs, 'V', 0x00000010
  end

  describe '#large_files' do
    it 'is a 1-bit flag' do
      expect(capabilities.large_files).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :large_files, 'V', 0x00000008
  end

  describe '#unicode' do
    it 'is a 1-bit flag' do
      expect(capabilities.unicode).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :unicode, 'V', 0x00000004
  end

  describe '#mpx_mode' do
    it 'is a 1-bit flag' do
      expect(capabilities.mpx_mode).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :mpx_mode, 'V', 0x00000002
  end

  describe '#raw_mode' do
    it 'is a 1-bit flag' do
      expect(capabilities.raw_mode).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :raw_mode, 'V', 0x00000001
  end

  describe '#large_writex' do
    it 'is a 1-bit flag' do
      expect(capabilities.large_writex).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :large_writex, 'V', 0x00008000
  end

  describe '#large_readx' do
    it 'is a 1-bit flag' do
      expect(capabilities.large_readx).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :large_readx, 'V', 0x00004000
  end

  describe '#info_level_passthru' do
    it 'is a 1-bit flag' do
      expect(capabilities.info_level_passthru).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :info_level_passthru, 'V', 0x00002000
  end

  describe '#dfs' do
    it 'is a 1-bit flag' do
      expect(capabilities.dfs).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :dfs, 'V', 0x00001000
  end

  describe '#reserved1' do
    it 'is a 1-bit flag' do
      expect(capabilities.reserved1).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved1).to eq 0
    end
  end

  describe '#bulk_transfer' do
    it 'is a 1-bit flag' do
      expect(capabilities.bulk_transfer).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(capabilities.bulk_transfer).to eq 0
    end
  end

  describe '#nt_find' do
    it 'is a 1-bit flag' do
      expect(capabilities.nt_find).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :nt_find, 'V', 0x00000200
  end

  describe '#lock_and_read' do
    it 'is a 1-bit flag' do
      expect(capabilities.lock_and_read).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :lock_and_read, 'V', 0x00000100
  end

  describe '#unix' do
    it 'is a 1-bit flag' do
      expect(capabilities.unix).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :unix, 'V', 0x00800000
  end

  describe '#reserved2' do
    it 'is a 6-bit reserved space' do
      expect(capabilities.reserved2).to be_a BinData::Bit6
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved2).to eq 0
    end
  end

  describe '#lwio' do
    it 'is a 1-bit flag' do
      expect(capabilities.lwio).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :lwio, 'V', 0x00010000
  end

  describe '#extended_security' do
    it 'is a 1-bit flag' do
      expect(capabilities.extended_security).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :extended_security, 'V', 0x80000000
  end

  describe '#reserved3' do
    it 'is a 1-bit flag' do
      expect(capabilities.reserved3).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved3).to eq 0
    end
  end

  describe '#dynamic_reauth' do
    it 'is a 1-bit flag' do
      expect(capabilities.dynamic_reauth).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :dynamic_reauth, 'V', 0x20000000
  end

  describe '#reserved4' do
    it 'is a 3-bit reserved space' do
      expect(capabilities.reserved4).to be_a BinData::Bit3
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved1).to eq 0
    end
  end

  describe '#compressed_data' do
    it 'is a 1-bit flag' do
      expect(capabilities.compressed_data).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :compressed_data, 'V', 0x02000000
  end

  describe '#reserved5' do
    it 'is a 1-bit flag' do
      expect(capabilities.reserved5).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved5).to eq 0
    end
  end
end
