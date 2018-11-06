require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::SessionSetupLegacyRequest do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP
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

    it { is_expected.to respond_to :andx_block }
    it { is_expected.to respond_to :max_buffer_size }
    it { is_expected.to respond_to :max_mpx_count }
    it { is_expected.to respond_to :vc_number }
    it { is_expected.to respond_to :session_key }
    it { is_expected.to respond_to :oem_password_length }
    it { is_expected.to respond_to :unicode_password_length }
    it { is_expected.to respond_to :capabilities }

    it 'has an AndXBlock' do
      expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :oem_password }
    it { is_expected.to respond_to :unicode_password }
    it { is_expected.to respond_to :padding }
    it { is_expected.to respond_to :account_name }
    it { is_expected.to respond_to :primary_domain }
    it { is_expected.to respond_to :native_os }
    it { is_expected.to respond_to :native_lan_man }
  end
end
