RSpec.describe RubySMB::SMB1::BitField::HeaderFlags do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :reply }
  it { is_expected.to respond_to :opbatch }
  it { is_expected.to respond_to :oplock }
  it { is_expected.to respond_to :canonicalized_paths }
  it { is_expected.to respond_to :case_insensitive }
  it { is_expected.to respond_to :reserved }
  it { is_expected.to respond_to :buf_avail }
  it { is_expected.to respond_to :lock_and_read_ok }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#reply' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.reply).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :reply, 'C', 0x80
  end

  describe '#opbatch' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.opbatch).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags.opbatch).to eq 0
    end

    it_behaves_like 'bit field with one flag set', :opbatch, 'C', 0x40
  end

  describe '#oplock' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.oplock).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags.oplock).to eq 0
    end

    it_behaves_like 'bit field with one flag set', :oplock, 'C', 0x20
  end

  describe '#canonicalized_paths' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.canonicalized_paths).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(flags.canonicalized_paths).to eq 1
    end

    it_behaves_like 'bit field with one flag set', :canonicalized_paths, 'C', 0x10
  end

  describe '#case_insensitive' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.case_insensitive).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(flags.case_insensitive).to eq 1
    end

    it_behaves_like 'bit field with one flag set', :case_insensitive, 'C', 0x08
  end

  describe '#reserved' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.reserved).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags.reserved).to eq 0
    end
  end

  describe '#buf_avail' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.buf_avail).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags.buf_avail).to eq 0
    end

    it_behaves_like 'bit field with one flag set', :buf_avail, 'C', 0x02
  end

  describe '#lock_and_read_ok' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.lock_and_read_ok).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :lock_and_read_ok, 'C', 0x01
  end
end
