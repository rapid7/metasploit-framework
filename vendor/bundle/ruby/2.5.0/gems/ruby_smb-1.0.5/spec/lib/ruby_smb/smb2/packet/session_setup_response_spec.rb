require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::SessionSetupResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :session_flags }
  it { is_expected.to respond_to :security_buffer_offset }
  it { is_expected.to respond_to :security_buffer_length }
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

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#set_type2_blob' do
    let(:fake_message) { 'foo' }

    it 'calls the #gss_type2 method to create a blob' do
      expect(RubySMB::Gss).to receive(:gss_type2).with(fake_message).and_return(fake_message)
      packet.set_type2_blob(fake_message)
    end

    it 'sets the security blob to the result from the GSS call' do
      expect(RubySMB::Gss).to receive(:gss_type2).with(fake_message).and_return(fake_message)
      packet.set_type2_blob(fake_message)
      expect(packet.buffer).to eq fake_message
    end

    it 'sets the security_blob_length field automatically' do
      expect(RubySMB::Gss).to receive(:gss_type2).with(fake_message).and_return(fake_message)
      packet.set_type2_blob(fake_message)
      expect(packet.security_buffer_length).to eq fake_message.length
    end
  end
end
