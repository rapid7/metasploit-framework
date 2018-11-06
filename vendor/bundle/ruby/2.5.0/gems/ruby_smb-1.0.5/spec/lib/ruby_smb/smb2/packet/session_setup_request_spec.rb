require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::SessionSetupRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :security_mode }
  it { is_expected.to respond_to :capabilities }
  it { is_expected.to respond_to :channel }
  it { is_expected.to respond_to :security_buffer_offset }
  it { is_expected.to respond_to :security_buffer_length }
  it { is_expected.to respond_to :previous_session_id }
  it { is_expected.to respond_to :buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::SESSION_SETUP
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
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
      expect(packet.buffer).to eq fake_message
    end

    it 'sets the security_blob_length field automatically' do
      expect(RubySMB::Gss).to receive(:gss_type1).with(fake_message).and_return(fake_message)
      packet.set_type1_blob(fake_message)
      expect(packet.security_buffer_length).to eq fake_message.length
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
      expect(packet.buffer).to eq fake_message
    end

    it 'sets the security_blob_length field automatically' do
      expect(RubySMB::Gss).to receive(:gss_type3).with(fake_message).and_return(fake_message)
      packet.set_type3_blob(fake_message)
      expect(packet.security_buffer_length).to eq fake_message.length
    end
  end
end
