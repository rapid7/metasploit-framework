RSpec.describe RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest do
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

    it 'is a Packet Trans Request ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::Trans::Request::ParameterBlock
    end

    describe '#total_parameter_count' do
      it 'is set to 0x0000' do
        expect(parameter_block.total_parameter_count).to eq(0x0000)
      end
    end

    describe '#total_data_count' do
      it 'has a default value equal to #data_count' do
        parameter_block.data_count = 5
        expect(parameter_block.total_data_count).to eq 5
      end
    end

    describe '#max_parameter_count' do
      it 'is set to 0x0000' do
        expect(parameter_block.max_parameter_count).to eq(0x0000)
      end
    end

    describe '#max_setup_count' do
      it 'is set to 0x00' do
        expect(parameter_block.max_setup_count).to eq(0x00)
      end
    end

    describe '#flags' do
      it 'is set to 0x0000' do
        expect(parameter_block.flags.to_binary_s.to_i).to eq(0x0000)
      end
    end

    describe '#timeout' do
      it 'is set to 0x00000000' do
        expect(parameter_block.timeout).to eq 0x00000000
      end
    end

    describe '#parameter_count' do
      it 'is set to 0x0000' do
        expect(parameter_block.parameter_count).to eq(0x0000)
      end
    end

    describe '#data_count' do
      it 'is set to the number of data bytes to be written to the named pipe' do
        packet.data_block.trans_data.write_data = "\x00\x01\x02\x03"
        expect(parameter_block.data_count).to eq 4
      end
    end

    describe '#setup_count' do
      it 'is set to 2' do
        expect(parameter_block.setup_count).to eq(2)
      end
    end

    describe '#setup' do
      it 'includes the TRANSACT_NMPIPE subcommand code' do
        expect(parameter_block.setup[0]).to eq(RubySMB::SMB1::Packet::Trans::Subcommands::TRANSACT_NMPIPE)
      end

      it 'includes the FID set to 0x0000 by default' do
        expect(parameter_block.setup[1]).to eq(0x0000)
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
      subject(:data) { data_block.trans_data }

      it { is_expected.to respond_to :write_data }

      describe '#write_data' do
        it 'is a String' do
          expect(data.write_data).to be_a BinData::String
        end

        it 'reads the number of bytes specified in parameter_block parameter_count field' do
          packet.parameter_block.data_count = 3
          data.write_data.read("ABCDEF")
          expect(data.write_data).to eq("ABC")
        end
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

  describe '#set_fid' do
    it 'sets the FID in the parameter_block #setup field' do
      fid = 0xAABB
      packet.set_fid(fid)
      expect(packet.parameter_block.setup[1]).to eq(fid)
    end
  end

  it 'reads its own binary representation and output the same packet' do
    # Adding some data to the ParameterBlock and DataBlock to make sure
    # paddings and lengths are handled correctly
    packet.set_fid(0xAABB)
    packet.data_block.trans_data.write_data = 'a'
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

