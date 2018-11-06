require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse do

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

    it 'is a standard Trans ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::Trans::Response::ParameterBlock
    end
  end

end