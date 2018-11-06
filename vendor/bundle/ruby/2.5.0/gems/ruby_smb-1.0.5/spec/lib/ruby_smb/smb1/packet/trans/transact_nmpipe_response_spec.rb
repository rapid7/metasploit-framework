RSpec.describe RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse do
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

    it 'is a Packet Trans Response ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::Trans::Response::ParameterBlock
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

    describe '#parameter_count' do
      it 'is set to 0x0000' do
        expect(parameter_block.parameter_count).to eq(0x0000)
      end
    end

    describe '#data_count' do
      it 'is set to the number of data bytes read from the named pipe' do
        packet.data_block.trans_data.read_data = "\x00\x01\x02\x03"
        expect(parameter_block.data_count).to eq 4
      end
    end

    describe '#setup_count' do
      it 'is set to 0' do
        expect(parameter_block.setup_count).to eq(0)
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
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
      subject(:data) { data_block.trans_data }

      it { is_expected.to respond_to :read_data }

      describe '#read_data' do
        it 'is a String' do
          expect(data.read_data).to be_a BinData::String
        end

        it 'reads the number of bytes specified in parameter_block parameter_count field' do
          packet.parameter_block.data_count = 3
          data.read_data.read("ABCDEF")
          expect(data.read_data).to eq("ABC")
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

  it 'reads its own binary representation and output the same packet' do
    # Adding some data to the DataBlock to make sure
    # paddings and lengths are handled correctly
    packet.data_block.trans_data.read_data = 'a'
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

