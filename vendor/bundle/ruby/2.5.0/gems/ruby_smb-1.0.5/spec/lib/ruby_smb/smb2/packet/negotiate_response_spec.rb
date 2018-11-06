RSpec.describe RubySMB::SMB2::Packet::NegotiateResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :security_mode }
  it { is_expected.to respond_to :dialect_revision }
  it { is_expected.to respond_to :negotiate_context_count }
  it { is_expected.to respond_to :server_guid }
  it { is_expected.to respond_to :capabilities }
  it { is_expected.to respond_to :max_transact_size }
  it { is_expected.to respond_to :max_read_size }
  it { is_expected.to respond_to :max_write_size }
  it { is_expected.to respond_to :system_time }
  it { is_expected.to respond_to :server_start_time }
  it { is_expected.to respond_to :security_buffer_offset }
  it { is_expected.to respond_to :security_buffer_length }
  it { is_expected.to respond_to :negotiate_context_offset }
  it { is_expected.to respond_to :security_buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::NEGOTIATE
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#structure_size' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.structure_size).to be_a BinData::Uint16le
    end

    it 'should have a default value of 65 as per the SMB2 spec' do
      expect(packet.structure_size).to eq 65
    end
  end

  describe '#security_mode' do
    it 'should be a SMB2 Security Mode BitField' do
      expect(packet.security_mode).to be_a RubySMB::SMB2::BitField::Smb2SecurityMode
    end
  end

  describe '#dialect_revision' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.dialect_revision).to be_a BinData::Uint16le
    end
  end

  describe '#negotiate_context_count' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.negotiate_context_count).to be_a BinData::Uint16le
    end

    it 'has a default value of 0' do
      expect(packet.negotiate_context_count).to eq 0
    end
  end

  describe '#server_guid' do
    it 'should be a binary string' do
      expect(packet.server_guid).to be_a BinData::String
    end

    it 'should be 16-bytes' do
      expect(packet.server_guid.do_num_bytes).to eq 16
    end
  end

  describe '#capabilities' do
    it 'should be a SMB2 Capabilities BitField' do
      expect(packet.capabilities).to be_a RubySMB::SMB2::BitField::Smb2Capabilities
    end
  end

  describe '#max_transact_size' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_transact_size).to be_a BinData::Uint32le
    end
  end

  describe '#max_read_size' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_read_size).to be_a BinData::Uint32le
    end
  end

  describe '#max_write_size' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_write_size).to be_a BinData::Uint32le
    end
  end

  describe '#system_time' do
    it 'should be a Filetime field' do
      expect(packet.system_time).to be_a RubySMB::Field::FileTime
    end
  end

  describe '#server_start_time' do
    it 'should be a Filetime field' do
      expect(packet.server_start_time).to be_a RubySMB::Field::FileTime
    end
  end

  describe '#security_buffer_offset' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.security_buffer_offset).to be_a BinData::Uint16le
    end
  end

  describe '#security_buffer_length' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.security_buffer_length).to be_a BinData::Uint16le
    end

    it 'should be the length of the security_buffer field' do
      packet.security_buffer = 'foobar'
      expect(packet.security_buffer_length).to eq 6
    end
  end

  describe '#negotiate_context_offset' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.negotiate_context_offset).to be_a BinData::Uint32le
    end
  end

  describe '#security_buffer' do
    it 'should be a binary string' do
      expect(packet.security_buffer).to be_a BinData::String
    end
  end
end
