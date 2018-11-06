require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::SessionSetupRequest do
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
    it { is_expected.to respond_to :security_blob_length }
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

    it { is_expected.to respond_to :security_blob }
    it { is_expected.to respond_to :native_os }
    it { is_expected.to respond_to :native_lan_man }
  end

  describe '#set_type1_blob' do
    let(:fake_message) { 'foo' }

    it 'calls the #gss_type1 method to create a blob' do
      expect(RubySMB::Gss).to receive(:gss_type1).with(fake_message).and_return(fake_message)
      packet.set_type1_blob(fake_message)
    end

    it 'sets the security blob to the result from the GSS call' do
      expect(RubySMB::Gss).to receive(:gss_type1).with(fake_message).and_return(fake_message)
      packet.set_type1_blob(fake_message)
      expect(packet.data_block.security_blob).to eq fake_message
    end

    it 'sets the security_blob_length field automatically' do
      expect(RubySMB::Gss).to receive(:gss_type1).with(fake_message).and_return(fake_message)
      packet.set_type1_blob(fake_message)
      expect(packet.parameter_block.security_blob_length).to eq fake_message.length
    end
  end

  describe '#set_type3_blob' do
    let(:fake_message) { 'foo' }

    it 'calls the #gss_type3 method to create a blob' do
      expect(RubySMB::Gss).to receive(:gss_type3).with(fake_message).and_return(fake_message)
      packet.set_type3_blob(fake_message)
    end

    it 'sets the security blob to the result from the GSS call' do
      expect(RubySMB::Gss).to receive(:gss_type3).with(fake_message).and_return(fake_message)
      packet.set_type3_blob(fake_message)
      expect(packet.data_block.security_blob).to eq fake_message
    end

    it 'sets the security_blob_length field automatically' do
      expect(RubySMB::Gss).to receive(:gss_type3).with(fake_message).and_return(fake_message)
      packet.set_type3_blob(fake_message)
      expect(packet.parameter_block.security_blob_length).to eq fake_message.length
    end
  end
end
