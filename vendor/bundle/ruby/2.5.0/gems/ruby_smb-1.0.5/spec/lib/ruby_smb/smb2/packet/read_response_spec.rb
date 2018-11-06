require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::ReadResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :data_offset }
  it { is_expected.to respond_to :data_length }
  it { is_expected.to respond_to :data_remaining }
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
      expect(header.command).to eq RubySMB::SMB2::Commands::READ
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  it 'should have a structure size of 17' do
    expect(packet.structure_size).to eq 17
  end

  it 'stores the offset to the data buffer' do
    expect(packet.data_offset).to eq packet.buffer.abs_offset
  end

  describe '#data_length' do
    it 'sets the length of the actual buffer' do
      packet.data_length = 12
      packet.buffer = 'hello world!'
      expect(packet.buffer.length).to eq 12
      packet.data_length = 5
      expect(packet.buffer).to eq 'hello'
    end
  end
end
