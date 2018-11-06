require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::EmptyPacket do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::ParameterBlock
    end

    it 'should be empty' do
      expect(parameter_block.to_binary_s).to eq "\x00"
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it 'should be empty' do
      expect(data_block.to_binary_s).to eq "\x00\x00"
    end
  end

  describe '#valid?' do
    before :example do
      packet.original_command = RubySMB::SMB1::Commands::SMB_COM_TREE_CONNECT
      packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_TREE_CONNECT
    end

    it 'returns true if the packet protocol ID and header command are valid' do
      expect(packet).to be_valid
    end

    it 'returns false if the packet protocol ID is wrong' do
      packet.smb_header.protocol = RubySMB::SMB2::SMB2_PROTOCOL_ID
      expect(packet).to_not be_valid
    end

    it 'returns false if the packet header command is wrong' do
      packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
      expect(packet).to_not be_valid
    end

    it 'returns false if the packet parameter block size is not 0' do
      packet.parameter_block.word_count = 10
      expect(packet).to_not be_valid
    end

    it 'returns false if the packet data block size is not 0' do
      packet.data_block.byte_count = 10
      expect(packet).to_not be_valid
    end
  end
end
