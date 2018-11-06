require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest do

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

    it 'is a standard Trans ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::Trans::Request::ParameterBlock
    end

    it 'should have a setup_count of 2' do
      expect(parameter_block.setup_count).to eq 2
    end

    it 'should have subcommand PEEK_NMPIPE' do
      expect(parameter_block.setup[0]).to eq RubySMB::SMB1::Packet::Trans::Subcommands::PEEK_NMPIPE
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'should have a name of \\PIPE\\' do
      expect(data_block.name).to eq "\\PIPE\\"
    end
  end

end