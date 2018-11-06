RSpec.describe RubySMB::SMB1::Packet::Trans::Response do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_TRANSACTION' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TRANSACTION
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

    it { is_expected.to respond_to :total_parameter_count }
    it { is_expected.to respond_to :total_data_count }
    it { is_expected.to respond_to :parameter_count }
    it { is_expected.to respond_to :parameter_offset }
    it { is_expected.to respond_to :parameter_displacement }
    it { is_expected.to respond_to :data_count }
    it { is_expected.to respond_to :data_offset }
    it { is_expected.to respond_to :parameter_displacement }
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

    describe '#parameter_displacement' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.parameter_displacement).to be_a BinData::Uint16le
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

    describe '#data_displacement' do
      it 'is a 16-bit unsigned integer' do
        expect(parameter_block.data_displacement).to be_a BinData::Uint16le
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

    it 'is a Packet Trans DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::Packet::Trans::DataBlock
    end

    it { is_expected.to respond_to :trans_parameters }
    it { is_expected.to respond_to :trans_data }

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

