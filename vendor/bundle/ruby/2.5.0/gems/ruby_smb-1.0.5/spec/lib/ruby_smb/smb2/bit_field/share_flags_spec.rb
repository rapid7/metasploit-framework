RSpec.describe RubySMB::SMB2::BitField::ShareFlags do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :dfs_root }
  it { is_expected.to respond_to :dfs }
  it { is_expected.to respond_to :encrypt }
  it { is_expected.to respond_to :hash_v2 }
  it { is_expected.to respond_to :hash_v1 }
  it { is_expected.to respond_to :force_oplock }
  it { is_expected.to respond_to :access_based_enum }
  it { is_expected.to respond_to :namespace_caching }
  it { is_expected.to respond_to :shared_delete }
  it { is_expected.to respond_to :restrict_exclusive_opens }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#dfs' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.dfs).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :dfs, 'V', 0x00000001
  end

  describe '#dfs_root' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.dfs_root).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :dfs_root, 'V', 0x00000002
  end

  describe '#restrict_exclusive_opens' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.restrict_exclusive_opens).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :restrict_exclusive_opens, 'V', 0x00000100
  end

  describe '#shared_delete' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.shared_delete).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :shared_delete, 'V', 0x00000200
  end

  describe '#namespace_caching' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.namespace_caching).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :namespace_caching, 'V', 0x00000400
  end

  describe '#access_based_enum' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.access_based_enum).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :access_based_enum, 'V', 0x00000800
  end

  describe '#force_oplock' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.force_oplock).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :force_oplock, 'V', 0x00001000
  end

  describe '#hash_v1' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.hash_v1).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :hash_v1, 'V', 0x00002000
  end

  describe '#hash_v2' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.hash_v2).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :hash_v2, 'V', 0x00004000
  end

  describe '#encrypt' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.encrypt).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :encrypt, 'V', 0x00008000
  end

  describe '#set_manual_caching' do
    it 'turns off the caching bits' do
      flags.set_manual_caching
      expect(flags.vdo_caching).to eq 0
      expect(flags.auto_caching).to eq 0
    end

    it 'has a value of 0x00000000' do
      flags.set_manual_caching
      flag_val = flags.to_binary_s
      flag_val = flag_val.unpack('V').first
      expect(flag_val).to eq 0x00000000
    end
  end

  describe '#set_auto_caching' do
    it 'turns on the auto_caching bit' do
      flags.set_auto_caching
      expect(flags.vdo_caching).to eq 0
      expect(flags.auto_caching).to eq 1
    end

    it 'has a value of 0x00000010' do
      flags.set_auto_caching
      flag_val = flags.to_binary_s
      flag_val = flag_val.unpack('V').first
      expect(flag_val).to eq 0x00000010
    end
  end

  describe '#set_vdo_caching' do
    it 'turns on the vdo_caching bits' do
      flags.set_vdo_caching
      expect(flags.vdo_caching).to eq 1
      expect(flags.auto_caching).to eq 0
    end

    it 'has a value of 0x00000020' do
      flags.set_vdo_caching
      flag_val = flags.to_binary_s
      flag_val = flag_val.unpack('V').first
      expect(flag_val).to eq 0x00000020
    end
  end

  describe '#set_no_caching' do
    it 'turns on all the caching bits' do
      flags.set_no_caching
      expect(flags.vdo_caching).to eq 1
      expect(flags.auto_caching).to eq 1
    end

    it 'has a value of 0x00000030' do
      flags.set_no_caching
      flag_val = flags.to_binary_s
      flag_val = flag_val.unpack('V').first
      expect(flag_val).to eq 0x00000030
    end
  end

  describe '#caching_type' do
    it 'returns VDO if only that flag is set' do
      flags.vdo_caching = 1
      expect(flags.caching_type).to eq :vdo
    end

    it 'returns Auto if only that flag is set' do
      flags.auto_caching = 1
      expect(flags.caching_type).to eq :auto
    end

    it 'returns No Caching if both caching flags are set' do
      flags.auto_caching = 1
      flags.vdo_caching = 1
      expect(flags.caching_type).to eq :no_caching
    end

    it 'returns Manual if neither caching flags are set' do
      flags.auto_caching = 0
      flags.vdo_caching = 0
      expect(flags.caching_type).to eq :manual
    end
  end
end
