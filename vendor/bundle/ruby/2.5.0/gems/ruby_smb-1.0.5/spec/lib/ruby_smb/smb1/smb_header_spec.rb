RSpec.describe RubySMB::SMB1::SMBHeader do
  subject(:header) { described_class.new }

  it { is_expected.to respond_to :protocol }
  it { is_expected.to respond_to :command }
  it { is_expected.to respond_to :nt_status }
  it { is_expected.to respond_to :flags }

  it { is_expected.to respond_to :pid_high }
  it { is_expected.to respond_to :security_features }
  it { is_expected.to respond_to :reserved }
  it { is_expected.to respond_to :tid }
  it { is_expected.to respond_to :pid_low }
  it { is_expected.to respond_to :uid }
  it { is_expected.to respond_to :mid }

  describe 'protocol' do
    it 'should be a 32-bit field per the SMB spec' do
      expect(header.protocol).to be_a BinData::Bit32
    end

    it 'should be hardcoded to SMB_PROTOCOL_ID by default per the SMB spec' do
      expect(header.protocol).to eq RubySMB::SMB1::SMB_PROTOCOL_ID
    end
  end

  describe 'command' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(header.command).to be_a BinData::Bit8
    end
  end

  describe 'nt_status' do
    it 'should be a NTStatus field' do
      expect(header.nt_status).to be_a RubySMB::Field::NtStatus
    end
  end

  describe 'flags' do
    it 'should be a HeaderFlags BitField' do
      expect(header.flags).to be_a RubySMB::SMB1::BitField::HeaderFlags
    end
  end

  describe 'flags2' do
    it 'should be a HeaderFlags2 BitField' do
      expect(header.flags2).to be_a RubySMB::SMB1::BitField::HeaderFlags2
    end
  end

  describe 'pid_high' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.pid_high).to be_a BinData::Uint16le
    end
  end

  describe 'security_features' do
    it 'should be a 8-byte string per the SMB spec' do
      expect(header.security_features).to be_a BinData::String
    end
  end

  describe 'reserved' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.reserved).to be_a BinData::Bit16
    end
  end

  describe 'tid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.tid).to be_a BinData::Bit16
    end
  end

  describe 'pid_low' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.pid_low).to be_a BinData::Uint16le
    end
  end

  describe 'uid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.uid).to be_a BinData::Bit16
    end
  end

  describe 'mid' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(header.mid).to be_a BinData::Uint16le
    end
  end

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
end
