require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::QueryDirectoryResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_QUERY_DIRECTORY' do
      expect(header.command).to eq RubySMB::SMB2::Commands::QUERY_DIRECTORY
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  it 'should have a structure size of 33' do
    expect(packet.structure_size).to eq 9
  end

  it 'has an offset pointer to the buffer field' do
    expect(packet.buffer_offset).to eq packet.buffer.abs_offset
  end

  it 'has a length value for the buffer field' do
    expect(packet.buffer_length).to eq packet.buffer.do_num_bytes
  end

  describe '#results' do
    let(:names1) {
      names = RubySMB::Fscc::FileInformation::FileNamesInformation.new
      names.file_name = 'test.txt'
      names.next_offset = names.do_num_bytes
      names
    }

    let(:names2) {
      names = RubySMB::Fscc::FileInformation::FileNamesInformation.new
      names.file_name = '..'
      names
    }

    let(:names_array) { [names1, names2] }

    let(:names_blob) { names_array.collect(&:to_binary_s).join('') }

    it 'returns an array of parsed Fileinformation structs' do
      packet.buffer = names_blob
      expect(packet.results(RubySMB::Fscc::FileInformation::FileNamesInformation)).to eq names_array
    end

    context 'when the File Information is not a valid' do
      it 'raises an InvalidPacket exception' do
        packet.buffer = names_blob
        allow(RubySMB::Fscc::FileInformation::FileNamesInformation).to receive(:read).and_raise(IOError)
        expect { packet.results(RubySMB::Fscc::FileInformation::FileNamesInformation) }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end
  end
end
