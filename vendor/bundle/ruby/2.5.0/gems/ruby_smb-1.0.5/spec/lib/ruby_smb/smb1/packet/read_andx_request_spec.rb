RSpec.describe RubySMB::SMB1::Packet::ReadAndxRequest do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_READ_ANDX' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_READ_ANDX
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

    it 'is little endian' do
      expect(parameter_block.get_parameter(:endian).endian).to eq :little
    end

    describe '#word_count' do
      it 'is set to the correct default value' do
        expect(parameter_block.word_count).to eq(0x0A)
      end
    end

    it { is_expected.to respond_to :andx_block }
    it { is_expected.to respond_to :fid }
    it { is_expected.to respond_to :offset }
    it { is_expected.to respond_to :max_count_of_bytes_to_return }
    it { is_expected.to respond_to :min_count_of_bytes_to_return }
    it { is_expected.to respond_to :timeout_or_max_count_high }
    it { is_expected.to respond_to :remaining }
    it { is_expected.to respond_to :offset_high }
    it { is_expected.to respond_to :read_from_named_pipe }

    describe '#andx_block' do
      it 'is a AndXBlock struct' do
        expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
      end
    end

    describe '#timeout_or_max_count_high' do
      it 'is a #timeout field when the target is a named pipe' do
        parameter_block.read_from_named_pipe = true
        expect(parameter_block.timeout_or_max_count_high).to respond_to :timeout
        expect(parameter_block.timeout_or_max_count_high).not_to respond_to :max_count_high
      end

      it 'is a #max_count_high field when the target is a file or a directory' do
        parameter_block.read_from_named_pipe = false
        expect(parameter_block.timeout_or_max_count_high).not_to respond_to :timeout
        expect(parameter_block.timeout_or_max_count_high).to respond_to :max_count_high
      end
    end

    describe '#offset_high' do
      it 'exists when word_count is 0x0C' do
        parameter_block.word_count = 0x0C
        expect(parameter_block.offset_high?).to be true
      end

      it 'does not exist when word_count is 0x0A' do
        parameter_block.word_count = 0x0A
        expect(parameter_block.offset_high?).to be false
      end
    end

    describe '#read_from_named_pipe' do
      it 'is set to the correct default value' do
        expect(parameter_block.read_from_named_pipe).to eq(false)
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it 'should be empty' do
      expect(data_block.byte_count).to eq(0)
    end
  end

  describe '#set_read_from_named_pipe' do
    it 'sets the #read_from_named_pipe variable to true' do
      packet.parameter_block.read_from_named_pipe = false
      packet.set_read_from_named_pipe(true)
      expect(packet.parameter_block.read_from_named_pipe).to be true
    end

    it 'sets the #read_from_named_pipe variable to false' do
      packet.parameter_block.read_from_named_pipe = true
      packet.set_read_from_named_pipe(false)
      expect(packet.parameter_block.read_from_named_pipe).to be false
    end

    it 'raises an exception when the value is a String' do
      expect { packet.set_read_from_named_pipe('true') }.to raise_error(ArgumentError)
    end

    it 'raises an exception when the value is a Numeric' do
      expect { packet.set_read_from_named_pipe(1) }.to raise_error(ArgumentError)
    end

    it 'raises an exception when the value is a Symbol' do
      expect { packet.set_read_from_named_pipe(:true) }.to raise_error(ArgumentError)
    end
  end

  describe '#set_64_bit_offset' do
    it 'sets the #word_count field to 0x0C when passing true' do
      packet.parameter_block.word_count = 0
      packet.set_64_bit_offset(true)
      expect(packet.parameter_block.word_count).to eq(0x0C)
    end

    it 'sets the #word_count field to 0x0A when passing false' do
      packet.parameter_block.word_count = 0
      packet.set_64_bit_offset(false)
      expect(packet.parameter_block.word_count).to eq(0x0A)
    end

    it 'raises an exception when the value is a String' do
      expect { packet.set_64_bit_offset('true') }.to raise_error(ArgumentError)
    end

    it 'raises an exception when the value is a Numeric' do
      expect { packet.set_64_bit_offset(1) }.to raise_error(ArgumentError)
    end

    it 'raises an exception when the value is a Symbol' do
      expect { packet.set_64_bit_offset(:true) }.to raise_error(ArgumentError)
    end
  end
end
