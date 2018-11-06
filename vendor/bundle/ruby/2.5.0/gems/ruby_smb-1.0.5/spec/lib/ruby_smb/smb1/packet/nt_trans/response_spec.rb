require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::NtTrans::Response do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT
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
    it { is_expected.to respond_to :data_count }
    it { is_expected.to respond_to :data_offset }
    it { is_expected.to respond_to :setup_count }

    describe 'parameter_count' do
      it 'is a count of bytes in the data_block trans2_parameters field' do
        packet.data_block.trans2_parameters = "\x00\x01\x02\x03"
        expect(parameter_block.parameter_count).to eq 4
      end
    end

    describe 'parameter_offset' do
      it ' contains the absolute_offset to the data_block trans2_parameters field' do
        expect(parameter_block.parameter_offset).to eq packet.data_block.trans2_parameters.abs_offset
      end
    end

    describe 'data_count' do
      it 'is a count of bytes in the data_block trans2_data field' do
        packet.data_block.trans2_data = "\x00\x01\x02\x03"
        expect(parameter_block.data_count).to eq 4
      end
    end

    describe 'data_offset' do
      it 'contains the absolute_offset to the data_block trans2_data field' do
        expect(parameter_block.data_offset).to eq packet.data_block.trans2_data.abs_offset
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is the same as a NtTrans Request DataBlocjk' do
      expect(data_block).to be_a RubySMB::SMB1::Packet::NtTrans::Request::DataBlock
    end
  end
end
