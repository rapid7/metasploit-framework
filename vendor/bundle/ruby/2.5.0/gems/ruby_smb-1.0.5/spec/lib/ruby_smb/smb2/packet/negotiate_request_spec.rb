RSpec.describe RubySMB::SMB2::Packet::NegotiateRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :dialect_count }
  it { is_expected.to respond_to :security_mode }
  it { is_expected.to respond_to :reserved1 }
  it { is_expected.to respond_to :capabilities }
  it { is_expected.to respond_to :client_guid }
  it { is_expected.to respond_to :client_start_time }
  it { is_expected.to respond_to :dialects }

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

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#structure_size' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.structure_size).to be_a BinData::Uint16le
    end

    it 'should have a default value of 36 as per the SMB2 spec' do
      expect(packet.structure_size).to eq 36
    end
  end

  describe '#dialect_count' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.dialect_count).to be_a BinData::Uint16le
    end
  end

  describe '#security_mode' do
    it 'should be a SMB2 Security Mode BitField' do
      expect(packet.security_mode).to be_a RubySMB::SMB2::BitField::Smb2SecurityMode
    end
  end

  describe '#capabilities' do
    it 'should be a SMB2 Capabilities BitField' do
      expect(packet.capabilities).to be_a RubySMB::SMB2::BitField::Smb2Capabilities
    end
  end

  describe '#client_guid' do
    it 'should be a binary string' do
      expect(packet.client_guid).to be_a BinData::String
    end

    it 'should be 16-bytes' do
      expect(packet.client_guid.do_num_bytes).to eq 16
    end
  end

  describe '#client_start_time' do
    it 'should be a Filetime field' do
      expect(packet.client_start_time).to be_a RubySMB::Field::FileTime
    end

    it 'should have a default value of 0 as per the SMB2 spec' do
      expect(packet.client_start_time).to eq 0
    end
  end

  describe '#dialects' do
    it 'is an array field as per the SMB spec' do
      expect(packet.dialects).to be_a BinData::Array
    end
  end

  describe '#add_dialect' do
    it 'adds the dialect to the Dialects array' do
      packet.add_dialect 0x0201
      expect(packet.dialects).to include(0x0201)
    end

    it 'updates the #dialect_count field' do
      packet.add_dialect 0x0201
      expect(packet.dialect_count).to eq 1
    end
  end

  describe '#set_dialects' do
    before(:each) do
      packet.add_dialect 0x0201
    end

    let(:dialect_set) { [0x0202, 0x0210, 0x0300] }

    it 'removes the existing dialects' do
      packet.set_dialects dialect_set
      expect(packet.dialects).to_not include(0x0201)
    end

    it 'sets #dialects to exacty what is supplied' do
      packet.set_dialects dialect_set
      expect(packet.dialects).to match_array(dialect_set)
    end

    it 'sets the #dialect_count field correctly' do
      packet.set_dialects dialect_set
      expect(packet.dialect_count).to eq 3
    end
  end
end
