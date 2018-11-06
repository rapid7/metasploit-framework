RSpec.describe RubySMB::SMB1::Packet::Trans::Request do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_TRANSACTION' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TRANSACTION
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::ParameterBlock
    end

    it { is_expected.to respond_to :total_parameter_count }
    it { is_expected.to respond_to :total_data_count }
    it { is_expected.to respond_to :max_parameter_count }
    it { is_expected.to respond_to :max_data_count }
    it { is_expected.to respond_to :max_setup_count }
    it { is_expected.to respond_to :flags }
    it { is_expected.to respond_to :timeout }
    it { is_expected.to respond_to :parameter_count }
    it { is_expected.to respond_to :parameter_offset }
    it { is_expected.to respond_to :data_count }
    it { is_expected.to respond_to :data_offset }
    it { is_expected.to respond_to :setup_count }
    it { is_expected.to respond_to :setup }

    describe '#total_parameter_count' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.total_parameter_count).to be_a BinData::Uint16le
      end

      it 'has a default value equal to #parameter_count' do
        parameter_block.parameter_count = 5
        expect(parameter_block.total_parameter_count).to eq 5
      end
    end

    describe '#total_data_count' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.total_data_count).to be_a BinData::Uint16le
      end

      it 'has a default value equal to #data_count' do
        parameter_block.data_count = 5
        expect(parameter_block.total_data_count).to eq 5
      end
    end

    describe '#max_parameter_count' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.max_parameter_count).to be_a BinData::Uint16le
      end

      it 'has the default value MAX_PARAMETER_COUNT' do
        expect(parameter_block.max_parameter_count).to eq RubySMB::SMB1::Packet::Trans::MAX_PARAMETER_COUNT
      end
    end

    describe '#max_data_count' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.max_data_count).to be_a BinData::Uint16le
      end

      it 'has the default value MAX_DATA_COUNT' do
        expect(parameter_block.max_data_count).to eq RubySMB::SMB1::Packet::Trans::MAX_DATA_COUNT
      end
    end

    describe '#max_setup_count' do
      it 'is a 8-bit unsigned integer' do
        expect(parameter_block.max_setup_count).to be_a BinData::Uint8
      end

      it 'has the default value MAX_SETUP_COUNT' do
        expect(parameter_block.max_setup_count).to eq RubySMB::SMB1::Packet::Trans::MAX_SETUP_COUNT
      end
    end

    describe '#flags' do
      it 'is a trans_flags BitField' do
        expect(parameter_block.flags).to be_a RubySMB::SMB1::BitField::TransFlags
      end
    end

    describe '#timeout' do
      it 'is a 32-bit unsigned integer' do
        expect(parameter_block.timeout).to be_a BinData::Uint32le
      end

      it 'has a default value of 0x00000000' do
        expect(parameter_block.timeout).to eq 0x00000000
      end
    end

    describe '#parameter_count' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.parameter_count).to be_a BinData::Uint16le
      end

      it 'is a count of bytes in the data_block trans_parameters field' do
        packet.data_block.trans_parameters = "\x00\x01\x02\x03"
        expect(parameter_block.parameter_count).to eq 4
      end
    end

    describe '#parameter_offset' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.parameter_offset).to be_a BinData::Uint16le
      end

      it ' contains the absolute_offset to the data_block trans_parameters field' do
        expect(parameter_block.parameter_offset).to eq packet.data_block.trans_parameters.abs_offset
      end
    end

    describe '#data_count' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.data_count).to be_a BinData::Uint16le
      end

      it 'is a count of bytes in the data_block trans_data field' do
        packet.data_block.trans_data = "\x00\x01\x02\x03"
        expect(parameter_block.data_count).to eq 4
      end
    end

    describe '#data_offset' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.data_offset).to be_a BinData::Uint16le
      end

      it 'contains the absolute_offset to the data_block trans_data field' do
        expect(parameter_block.data_offset).to eq packet.data_block.trans_data.abs_offset
      end
    end

    describe '#setup_count' do
      it 'is a 8-bit unsigned integer' do
        expect(parameter_block.setup_count).to be_a BinData::Uint8
      end

      it 'is a count of words in setup field' do
        parameter_block.setup << 0x0102
        parameter_block.setup << 0x0304
        expect(parameter_block.setup_count).to eq 2
      end
    end

    describe '#setup' do
      it 'is an Array' do
        expect(parameter_block.setup).to be_a BinData::Array
      end

      it 'has #setup_count elements' do
        parameter_block.setup_count = 3
        expect(parameter_block.setup.length).to eq 3
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :name }
    it { is_expected.to respond_to :trans_parameters }
    it { is_expected.to respond_to :trans_data }

    describe '#pad_name' do
      context 'when the UNICODE flag is not set in the Flags2 field of the SMB Header' do
        it 'does not exists' do
          expect(data_block).to_not be_pad_name
        end
      end

      context 'when the UNICODE flag is set in the Flags2 field of the SMB Header' do
        before :example do
          packet.smb_header.flags2.unicode = 1
        end

        it 'exists' do
          expect(data_block).to be_pad_name
        end

        it 'is one null byte when #name is not 2-byte aligned' do
          expect(data_block.pad_name).to eq("\x00")
        end

        it 'should keep #name 2-byte aligned' do
          expect(data_block.name.abs_offset % 2).to eq 0
        end
      end
    end

    describe '#name' do
      context 'when the UNICODE flag is not set in the Flags2 field of the SMB Header' do
        it 'is a Stringz' do
          expect(data_block.name.current_choice).to be_a BinData::Stringz
        end

        it 'is ASCII encoded' do
          expect(data_block.name.encoding.name).to eq("ASCII-8BIT")
        end

        it 'is set to "\\PIPE\\\x00" by default' do
          expect(data_block.name.to_binary_s).to eq("\\PIPE\\\x00")
        end

        it 'adds a NULL terminator to the string' do
          str = "test"
          data_block.name = str
          expect(data_block.name.to_binary_s).to eq(str + "\x00")
        end
      end

      context 'when the UNICODE flag is set in the Flags2 field of the SMB Header' do
        before :example do
          packet.smb_header.flags2.unicode = 1
        end

        it 'is a Stringz16' do
          expect(data_block.name.current_choice).to be_a RubySMB::Field::Stringz16
        end

        it 'is UTF-16LE encoded' do
          expect(data_block.name.encoding.name).to eq("UTF-16LE")
        end

        it 'is set to the null terminated unicode string "\\PIPE\\" by default' do
          binary_str = "\\PIPE\\\x00".encode('utf-16le').force_encoding('ASCII')
          expect(data_block.name.to_binary_s).to eq(binary_str)
        end

        it 'adds a NULL terminator to the string' do
          str = "test"
          data_block.name = str
          binary_str = (str + "\x00").encode('utf-16le').force_encoding('ASCII')
          expect(data_block.name.to_binary_s).to eq(binary_str)
        end
      end

      context 'when switching from ASCII to UNICODE' do
        it 'encodes the same string to UNICODE' do
          packet = RubySMB::SMB1::Packet::Trans::Request.new
          data_block = packet.data_block

          str = "test"
          data_block.name = str
          expect(data_block.name.to_binary_s).to eq(str + "\x00")
          packet.smb_header.flags2.unicode = 1
          binary_str = (str + "\x00").encode('utf-16le').force_encoding('ASCII')
          expect(data_block.name.to_binary_s).to eq(binary_str)
        end
      end
    end

    describe '#trans_parameters' do
      it 'is a String' do
        expect(data_block.trans_parameters).to be_a BinData::String
      end

      it 'reads the number of bytes specified in parameter_block parameter_count field' do
        packet.parameter_block.parameter_count = 3
        data_block.trans_parameters.read("ABCDEF")
        expect(data_block.trans_parameters).to eq("ABC")
      end
    end

    describe '#trans_data' do
      it 'is a String' do
        expect(data_block.trans_data).to be_a BinData::String
      end

      it 'reads the number of bytes specified in parameter_block parameter_count field' do
        packet.parameter_block.data_count = 3
        data_block.trans_data.read("ABCDEF")
        expect(data_block.trans_data).to eq("ABC")
      end
    end

    describe '#pad1' do
      it 'should keep #trans_parameters 4-byte aligned' do
        expect(data_block.trans_parameters.abs_offset % 4).to eq 0
      end
    end

    describe '#pad2' do
      it 'should keep #trans_data 4-byte aligned' do
        data_block.trans_parameters = 'a'
        expect(data_block.trans_data.abs_offset % 4).to eq 0
      end
    end
  end

  it 'reads its own binary representation and output the same packet' do
    # Adding some data to the DataBlock to make sure paddings are handled correctly
    packet.data_block.trans_parameters = 'a'
    packet.data_block.trans_data = 'b'
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

