RSpec.describe RubySMB::SMB1::Packet::WriteAndxRequest do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_WRITE_ANDX' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_WRITE_ANDX
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
        expect(parameter_block.word_count).to eq(0x0C)
      end
    end

    it { is_expected.to respond_to :andx_block }
    it { is_expected.to respond_to :fid }
    it { is_expected.to respond_to :offset }
    it { is_expected.to respond_to :timeout }
    it { is_expected.to respond_to :write_mode }
    it { is_expected.to respond_to :remaining }
    it { is_expected.to respond_to :data_length_high }
    it { is_expected.to respond_to :data_length }
    it { is_expected.to respond_to :data_offset }
    it { is_expected.to respond_to :offset_high }

    describe '#andx_block' do
      it 'is a AndXBlock struct' do
        expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
      end
    end

    describe '#write_mode' do
      subject(:write_mode) { parameter_block.write_mode }

      it { is_expected.to respond_to :msg_start }
      it { is_expected.to respond_to :raw_mode }
      it { is_expected.to respond_to :read_bytes_available }
      it { is_expected.to respond_to :writethrough_mode }

      it 'is little endian' do
        expect(write_mode.get_parameter(:endian).endian).to eq :little
      end

      describe '#msg_start' do
        it 'is a 1-bit flag' do
          expect(write_mode.msg_start).to be_a BinData::Bit1
        end

        it_behaves_like 'bit field with one flag set', :msg_start, 'v', 0x0008
      end

      describe '#raw_mode' do
        it 'is a 1-bit flag' do
          expect(write_mode.raw_mode).to be_a BinData::Bit1
        end

        it_behaves_like 'bit field with one flag set', :raw_mode, 'v', 0x0004
      end

      describe '#read_bytes_available' do
        it 'is a 1-bit flag' do
          expect(write_mode.read_bytes_available).to be_a BinData::Bit1
        end

        it_behaves_like 'bit field with one flag set', :read_bytes_available, 'v', 0x0002
      end

      describe '#writethrough_mode' do
        it 'is a 1-bit flag' do
          expect(write_mode.writethrough_mode).to be_a BinData::Bit1
        end

        it_behaves_like 'bit field with one flag set', :writethrough_mode, 'v', 0x0001
      end
    end

    describe '#offset_high' do
      it 'exists when word_count is 0x0E' do
        parameter_block.word_count = 0x0E
        expect(parameter_block.offset_high?).to be true
      end

      it 'does not exist when word_count is 0x0C' do
        parameter_block.word_count = 0x0C
        expect(parameter_block.offset_high?).to be false
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :pad }
    it { is_expected.to respond_to :data }
  end

  describe '#set_64_bit_offset' do
    it 'sets the #word_count field to 0x0E when passing true' do
      packet.parameter_block.word_count = 0
      packet.set_64_bit_offset(true)
      expect(packet.parameter_block.word_count).to eq(0x0E)
    end

    it 'sets the #word_count field to 0x0C when passing false' do
      packet.parameter_block.word_count = 0
      packet.set_64_bit_offset(false)
      expect(packet.parameter_block.word_count).to eq(0x0C)
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
