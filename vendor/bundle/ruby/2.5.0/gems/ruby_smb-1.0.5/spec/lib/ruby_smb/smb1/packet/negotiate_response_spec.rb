RSpec.describe RubySMB::SMB1::Packet::NegotiateResponse do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::ParameterBlock
    end

    it { is_expected.to respond_to :dialect_index }
    it { is_expected.to respond_to :security_mode }
    it { is_expected.to respond_to :max_mpx_count }
    it { is_expected.to respond_to :max_number_vcs }
    it { is_expected.to respond_to :max_buffer_size }
    it { is_expected.to respond_to :max_raw_size }
    it { is_expected.to respond_to :session_key }
    it { is_expected.to respond_to :capabilities }
    it { is_expected.to respond_to :system_time }
    it { is_expected.to respond_to :server_time_zone }
    it { is_expected.to respond_to :challenge_length }

    describe '#dialect_index' do
      it 'is a 16-bit Unsigned Integer' do
        expect(parameter_block.dialect_index).to be_a BinData::Uint16le
      end
    end

    describe '#security_mode' do
      it 'is a SecurityMode bit-field' do
        expect(parameter_block.security_mode).to be_a RubySMB::SMB1::BitField::SecurityMode
      end
    end

    describe '#max_mpx_count' do
      it 'is a 16-bit Unsigned Integer' do
        expect(parameter_block.max_mpx_count).to be_a BinData::Uint16le
      end
    end

    describe '#max_number_vcs' do
      it 'is a 16-bit Unsigned Integer' do
        expect(parameter_block.max_number_vcs).to be_a BinData::Uint16le
      end
    end

    describe '#max_buffer_size' do
      it 'is a 32-bit Unsigned Integer' do
        expect(parameter_block.max_buffer_size).to be_a BinData::Uint32le
      end
    end

    describe '#max_raw_size' do
      it 'is a 32-bit Unsigned Integer' do
        expect(parameter_block.max_raw_size).to be_a BinData::Uint32le
      end
    end

    describe '#session_key' do
      it 'is a 32-bit Unsigned Integer' do
        expect(parameter_block.session_key).to be_a BinData::Uint32le
      end
    end

    describe '#capabilities' do
      it 'is a Capabilities bit-field' do
        expect(parameter_block.capabilities).to be_a RubySMB::SMB1::BitField::Capabilities
      end
    end

    describe '#system_time' do
      it 'is a FileTime field' do
        expect(parameter_block.system_time).to be_a RubySMB::Field::FileTime
      end
    end

    describe '#server_time_zone' do
      it 'is a 16-bit Signed Integer' do
        expect(parameter_block.server_time_zone).to be_a BinData::Int16le
      end
    end

    describe '#challenge_length' do
      it 'is a 8-bit Unsigned Integer' do
        expect(parameter_block.challenge_length).to be_a BinData::Uint8
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :challenge }
    it { is_expected.to respond_to :domain_name }
    it { is_expected.to respond_to :server_name }

    describe '#challenge' do
      it 'is a sized string of bytes' do
        expect(data_block.challenge).to be_a BinData::String
      end

      it 'is exactly 8-bytes long' do
        expect(data_block.challenge.length).to eq 8
      end
    end

    describe '#domain_name' do
      it 'is a Unicode Null-terminated string' do
        expect(data_block.domain_name).to be_a RubySMB::Field::Stringz16
      end
    end

    describe '#server_name' do
      it 'is a Unicode Null-terminated string' do
        expect(data_block.server_name).to be_a RubySMB::Field::Stringz16
      end
    end
  end

  describe '#valid?' do
    it 'should return true if the command value ix 0x72' do
      expect(packet.valid?).to be true
    end

    it 'should return false if the command value is not 0x72' do
      packet.smb_header.command = 0xff
      expect(packet.valid?).to be false
    end
  end

  context 'with dialects' do
    let(:dialects) do
      dialects = []
      dialects << RubySMB::SMB1::Dialect.read("\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00")
      dialects << RubySMB::SMB1::Dialect.read("\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00")
      dialects
    end

    describe '#dialects=' do
      it 'sets #dialects to the array of Dialects passed as argument' do
        packet.dialects = dialects
        expect(packet.instance_variable_get(:@dialects)).to eq dialects
      end

      it 'returns #dialects' do
        expect(packet.dialects = dialects).to eq dialects
      end

      it 'raises an exception when one of the element of dialects is not a Dialect object' do
        dialects << 'My Dialect'
        expect { packet.dialects = dialects }.to raise_error(ArgumentError)
      end
    end

    describe '#negotiated_dialect' do
      it 'returns an empty string if #dialects is empty' do
        expect(packet.negotiated_dialect).to eq ''
      end

      it 'returns the negotiated dialect' do
        packet.parameter_block.dialect_index = 1
        packet.dialects = dialects
        expect(packet.negotiated_dialect).to eq 'SMB 2.002'
      end
    end
  end
end
