require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::TreeConnectResponse do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TREE_CONNECT
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

    it { is_expected.to respond_to :andx_block }
    it { is_expected.to respond_to :optional_support }
    it { is_expected.to respond_to :access_rights }
    it { is_expected.to respond_to :guest_access_rights }

    it 'has an AndXBlock' do
      expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
    end

    context 'when #word_count is less than 5' do
      before :example do
        parameter_block.word_count = 3
      end

      it 'has #access_rights and #guest_access_rights fields disabled' do
        expect(parameter_block.andx_block?). to be true
        expect(parameter_block.optional_support?). to be true
        expect(parameter_block.access_rights?). to be false
        expect(parameter_block.guest_access_rights?). to be false
      end
    end

    context 'when #word_count is 5' do
      before :example do
        parameter_block.word_count = 5
      end

      it 'has the #guest_access_rights field disabled' do
        expect(parameter_block.andx_block?). to be true
        expect(parameter_block.optional_support?). to be true
        expect(parameter_block.access_rights?). to be true
        expect(parameter_block.guest_access_rights?). to be false
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :service }
    it { is_expected.to respond_to :native_file_system }
  end

  context 'when the connect is to a directory' do
    let(:directory_response) {
      packet = described_class.new
      packet.data_block.service = 'A:'
      packet
    }

    it 'returns a DirectoryAccessMask from #access_rights' do
      expect(directory_response.access_rights).to be_a RubySMB::SMB1::BitField::DirectoryAccessMask
    end

    it 'returns a DirectoryAccessMask from #guest_access_rights' do
      expect(directory_response.guest_access_rights).to be_a RubySMB::SMB1::BitField::DirectoryAccessMask
    end
  end

  context 'when the connect is to a named pipe' do
    let(:file_response) {
      packet = described_class.new
      packet.data_block.service = 'IPC'
      packet
    }

    it 'returns a FileAccessMask from #access_rights' do
      expect(file_response.access_rights).to be_a RubySMB::SMB1::BitField::FileAccessMask
    end

    it 'returns a FileAccessMask from #guest_access_rights' do
      expect(file_response.guest_access_rights).to be_a RubySMB::SMB1::BitField::FileAccessMask
    end
  end

  describe '#access_rights' do
    it 'is a DirectoryAccessMask if the Tree is a directory' do
      allow(packet).to receive(:is_directory?).and_return(true)
      expect(packet.access_rights).to be_a RubySMB::SMB1::BitField::DirectoryAccessMask
    end

    it 'is a FileAccessMask if the Tree is not a directory' do
      allow(packet).to receive(:is_directory?).and_return(false)
      expect(packet.access_rights).to be_a RubySMB::SMB1::BitField::FileAccessMask
    end

    context 'when it is not a valid FileAccessMask' do
      it 'raises an InvalidBitField exception' do
        allow(packet).to receive(:is_directory?).and_return(false)
        allow(RubySMB::SMB1::BitField::FileAccessMask).to receive(:read).and_raise(IOError)
        expect { packet.access_rights }.to raise_error(RubySMB::Error::InvalidBitField)
      end
    end
  end

  describe '#guest_access_rights' do
    it 'is a DirectoryAccessMask if the Tree is a directory' do
      allow(packet).to receive(:is_directory?).and_return(true)
      expect(packet.guest_access_rights).to be_a RubySMB::SMB1::BitField::DirectoryAccessMask
    end

    it 'is a FileAccessMask if the Tree is not a directory' do
      allow(packet).to receive(:is_directory?).and_return(false)
      expect(packet.guest_access_rights).to be_a RubySMB::SMB1::BitField::FileAccessMask
    end

    context 'when it is not a valid FileAccessMask' do
      it 'raises an InvalidBitField exception' do
        allow(packet).to receive(:is_directory?).and_return(false)
        allow(RubySMB::SMB1::BitField::FileAccessMask).to receive(:read).and_raise(IOError)
        expect { packet.guest_access_rights }.to raise_error(RubySMB::Error::InvalidBitField)
      end
    end
  end
end
