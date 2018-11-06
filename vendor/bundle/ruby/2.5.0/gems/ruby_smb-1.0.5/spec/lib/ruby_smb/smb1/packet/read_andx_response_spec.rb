RSpec.describe RubySMB::SMB1::Packet::ReadAndxResponse do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_READ_ANDX' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_READ_ANDX
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

    it 'is little endian' do
      expect(parameter_block.get_parameter(:endian).endian).to eq :little
    end

    it { is_expected.to respond_to :andx_block }
    it { is_expected.to respond_to :available }
    it { is_expected.to respond_to :data_compaction_mode }
    it { is_expected.to respond_to :data_length }
    it { is_expected.to respond_to :data_offset }
    it { is_expected.to respond_to :data_length_high }

    describe '#andx_block' do
      it 'is a AndXBlock struct' do
        expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
      end
    end

    describe '#data_compaction_mode' do
      it 'is set to the correct default value' do
        expect(parameter_block.data_compaction_mode).to eq(0x0000)
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it 'is little endian' do
      expect(data_block.get_parameter(:endian).endian).to eq :little
    end

    it { is_expected.to respond_to :pad }
    it { is_expected.to respond_to :data }

    describe '#pad' do
      it 'does not exist if byte_count is zero (no data in the data_block)' do
        data_block.byte_count = 0
        expect(data_block.pad?).to be false
      end

      it 'does not exist if the data_length is equal to byte_count' do
        packet.parameter_block.data_length = 5
        data_block.byte_count = 5
        expect(data_block.pad?).to be false
      end

      it 'exists if the data_length is one byte less than byte_count' do
        packet.parameter_block.data_length = 4
        data_block.byte_count = 5
        expect(data_block.pad?).to be true
      end
    end

    describe '#data' do
      it 'reads the number of bytes specified in the data_length field' do
        data = 'Testing...'
        packet.parameter_block.data_length = 4
        data_block.data.read(data)
        expect(data_block.data).to eq(data[0, 4])
      end
    end
  end
end
