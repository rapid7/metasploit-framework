require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::WriteRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :data_offset }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :write_length }
  it { is_expected.to respond_to :write_offset }
  it { is_expected.to respond_to :file_id }
  it { is_expected.to respond_to :channel }
  it { is_expected.to respond_to :remaining_bytes }
  it { is_expected.to respond_to :channel_offset }
  it { is_expected.to respond_to :channel_length }
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
      expect(header.command).to eq RubySMB::SMB2::Commands::WRITE
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  it 'should have a structure size of 49' do
    expect(packet.structure_size).to eq 49
  end

  it 'stores the offset of the write buffer in #data_offset' do
    expect(packet.data_offset).to eq packet.buffer.abs_offset
  end

  it 'stores the length of the write buffer in #write_length' do
    packet.buffer = 'hello'
    expect(packet.write_length).to eq packet.buffer.length
  end
end
