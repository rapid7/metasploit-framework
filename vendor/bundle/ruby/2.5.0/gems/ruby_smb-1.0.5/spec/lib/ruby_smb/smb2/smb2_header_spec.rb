RSpec.describe RubySMB::SMB2::SMB2Header do
  subject(:header) { described_class.new }

  it { is_expected.to respond_to :protocol }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :credit_charge }
  it { is_expected.to respond_to :nt_status }
  it { is_expected.to respond_to :command }
  it { is_expected.to respond_to :credits }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :next_command }
  it { is_expected.to respond_to :message_id }
  it { is_expected.to respond_to :process_id }
  it { is_expected.to respond_to :tree_id }
  it { is_expected.to respond_to :session_id }
  it { is_expected.to respond_to :signature }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#protocol' do
    it 'is a 32-bit field' do
      expect(header.protocol).to be_a BinData::Bit32
    end

    it 'has a default value of the SMB2 ID' do
      expect(header.protocol).to eq RubySMB::SMB2::SMB2_PROTOCOL_ID
    end
  end

  describe '#structure_size' do
    it 'is a 16-bit unsigned integer' do
      expect(header.structure_size).to be_a BinData::Uint16le
    end

    it 'has a default value of 64 as per the SMB2 spec' do
      expect(header.structure_size).to eq 64
    end
  end

  describe '#credit_charge' do
    it 'is a 16-bit unsigned integer' do
      expect(header.credit_charge).to be_a BinData::Uint16le
    end

    it 'has a default value of 0' do
      expect(header.credit_charge).to eq 0
    end
  end

  describe '#nt_status' do
    it 'is a NTStatus field' do
      expect(header.nt_status).to be_a RubySMB::Field::NtStatus
    end

    it 'has a default value of 0' do
      expect(header.nt_status).to eq 0
    end
  end

  describe '#command' do
    it 'is a 16-bit unsigned integer' do
      expect(header.command).to be_a BinData::Uint16le
    end
  end

  describe '#credits' do
    it 'is a 16-bit unsigned integer' do
      expect(header.credits).to be_a BinData::Uint16le
    end
  end

  describe '#flags' do
    it 'is an smb2_header_flags field' do
      expect(header.flags).to be_a RubySMB::SMB2::BitField::Smb2HeaderFlags
    end
  end

  describe '#next_command' do
    it 'is a 32-bit unsigned integer' do
      expect(header.next_command).to be_a BinData::Uint32le
    end

    it 'has a default value of 0' do
      expect(header.next_command).to eq 0
    end
  end

  describe '#message_id' do
    it 'is a 64-bit unsigned integer' do
      expect(header.message_id).to be_a BinData::Uint64le
    end
  end

  describe '#process_id' do
    it 'is a 32-bit unsigned integer' do
      expect(header.process_id).to be_a BinData::Uint32le
    end

    it 'has a default value of 0x0000feff' do
      expect(header.process_id).to eq 0x0000feff
    end
  end

  describe '#tree_id' do
    it 'is a 32-bit unsigned integer' do
      expect(header.tree_id).to be_a BinData::Uint32le
    end
  end

  describe '#session_id' do
    it 'is a 64-bit unsigned integer' do
      expect(header.session_id).to be_a BinData::Uint64le
    end
  end

  describe '#signature' do
    it 'is a binary string' do
      expect(header.signature).to be_a BinData::String
    end

    it 'is 16 bytes' do
      expect(header.signature.do_num_bytes).to eq 16
    end
  end
end
