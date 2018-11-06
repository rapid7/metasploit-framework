require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::TreeConnectRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :path_offset }
  it { is_expected.to respond_to :path_length }
  it { is_expected.to respond_to :path }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::TREE_CONNECT
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#encode_path' do
    let(:path) { '\\192.168.1.1\\example' }
    let(:encoded_path) { path.encode('utf-16le').force_encoding('binary') }

    it 'sets the path string to a UTF-16LE version of the supplied string' do
      packet.encode_path(path)
      expect(packet.path).to eq encoded_path
    end

    it 'updates the #path_length' do
      packet.encode_path(path)
      expect(packet.path_length).to eq encoded_path.length
    end
  end
end
