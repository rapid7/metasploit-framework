RSpec.describe RubySMB::SMB2::BitField::FileAccessMask do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :read_attr }
  it { is_expected.to respond_to :delete_child }
  it { is_expected.to respond_to :execute }
  it { is_expected.to respond_to :write_ea }
  it { is_expected.to respond_to :read_ea }
  it { is_expected.to respond_to :append_data }
  it { is_expected.to respond_to :write_data }
  it { is_expected.to respond_to :read_data }
  it { is_expected.to respond_to :write_attr }
  it { is_expected.to respond_to :synchronize }
  it { is_expected.to respond_to :write_owner }
  it { is_expected.to respond_to :write_dac }
  it { is_expected.to respond_to :read_control }
  it { is_expected.to respond_to :delete_access }
  it { is_expected.to respond_to :generic_read }
  it { is_expected.to respond_to :generic_write }
  it { is_expected.to respond_to :generic_execute }
  it { is_expected.to respond_to :generic_all }
  it { is_expected.to respond_to :maximum }
  it { is_expected.to respond_to :system_security }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#read_data' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.read_data).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :read_data, 'V', 0x00000001
  end

  describe '#write_data' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.write_data).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :write_data, 'V', 0x00000002
  end

  describe '#append_data' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.append_data).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :append_data, 'V', 0x00000004
  end

  describe '#read_ea' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.read_ea).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :read_ea, 'V', 0x00000008
  end

  describe '#write_ea' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.write_ea).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :write_ea, 'V', 0x00000010
  end

  describe '#execute' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.execute).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :execute, 'V', 0x00000020
  end

  describe '#delete_child' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.delete_child).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :delete_child, 'V', 0x00000040
  end

  describe '#read_attr' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.read_attr).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :read_attr, 'V', 0x00000080
  end

  describe '#write_attr' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.write_attr).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :write_attr, 'V', 0x00000100
  end

  describe '#delete_access' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.delete_access).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :delete_access, 'V', 0x00010000
  end

  describe '#read_control' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.read_control).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :read_control, 'V', 0x00020000
  end

  describe '#write_dac' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.write_dac).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :write_dac, 'V', 0x00040000
  end

  describe '#write_owner' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.write_owner).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :write_owner, 'V', 0x00080000
  end

  describe '#synchronize' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.synchronize).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :synchronize, 'V', 0x00100000
  end

  describe '#system_security' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.system_security).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :system_security, 'V', 0x01000000
  end

  describe '#maximum' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.maximum).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :maximum, 'V', 0x02000000
  end

  describe '#generic_all' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.generic_all).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :generic_all, 'V', 0x10000000
  end

  describe '#generic_execute' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.generic_execute).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :generic_execute, 'V', 0x20000000
  end

  describe '#generic_write' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.generic_write).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :generic_write, 'V', 0x40000000
  end

  describe '#generic_read' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.generic_read).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :generic_read, 'V', 0x80000000
  end
end
