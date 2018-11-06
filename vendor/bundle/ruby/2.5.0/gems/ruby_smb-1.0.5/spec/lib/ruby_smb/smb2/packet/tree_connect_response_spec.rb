require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::TreeConnectResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :share_type }
  it { is_expected.to respond_to :share_flags }
  it { is_expected.to respond_to :capabilities }
  it { is_expected.to respond_to :maximal_access }

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

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#is_directory?' do
    it 'returns true if #share_type is 0x01' do
      packet.share_type = 0x01
      expect(packet.is_directory?).to be true
    end

    it 'returns false if #share_type is not 0x01' do
      packet.share_type = 0x02
      expect(packet.is_directory?).to be false
    end
  end

  describe '#access_rights' do
    it 'is a DirectoryAccessMask if the Tree is a directory' do
      allow(packet).to receive(:is_directory?).and_return(true)
      expect(packet.access_rights).to be_a RubySMB::SMB2::BitField::DirectoryAccessMask
    end

    it 'is a FileAccessMask if the Tree is not a directory' do
      allow(packet).to receive(:is_directory?).and_return(false)
      expect(packet.access_rights).to be_a RubySMB::SMB2::BitField::FileAccessMask
    end

    context 'when it is not a valid FileAccessMask' do
      it 'raises an InvalidBitField exception' do
        allow(packet).to receive(:is_directory?).and_return(false)
        allow(RubySMB::SMB2::BitField::FileAccessMask).to receive(:read).and_raise(IOError)
        expect { packet.access_rights }.to raise_error(RubySMB::Error::InvalidBitField)
      end
    end
  end
end
