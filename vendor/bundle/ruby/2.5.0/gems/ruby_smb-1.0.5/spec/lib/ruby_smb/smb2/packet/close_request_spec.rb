require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::CloseRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :file_id }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_CLOSE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::CLOSE
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  it 'should have a structure size of 24' do
    expect(packet.structure_size).to eq 24
  end

  describe '#file_id' do
    it 'should be an SMB FileID field' do
      expect(packet.file_id).to be_a RubySMB::Field::Smb2Fileid
    end
  end
end
