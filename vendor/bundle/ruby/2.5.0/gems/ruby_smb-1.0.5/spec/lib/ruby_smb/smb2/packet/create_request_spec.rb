require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::CreateRequest do
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

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::CREATE
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  it 'should have a structure size of 57' do
    expect(packet.structure_size).to eq 57
  end

  describe '#desired_access' do
    it 'should be a DirectoryAccessMask when the file is a directory' do
      packet.file_attributes.directory = 1
      access_mask = packet.desired_access.send(:current_choice)
      expect(access_mask.class).to eq RubySMB::SMB2::BitField::DirectoryAccessMask
    end

    it 'should be a FileAccessMask when the file is not a directory' do
      packet.file_attributes.directory = 0
      access_mask = packet.desired_access.send(:current_choice)
      expect(access_mask.class).to eq RubySMB::SMB2::BitField::FileAccessMask
    end
  end

  describe '#share_accesss' do
    subject(:flags) { packet.share_access }

    describe '#read_access' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(flags.read_access).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :read_access, 'V', 0x00000001
    end

    describe '#write_access' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(flags.write_access).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :write_access, 'V', 0x00000002
    end

    describe '#delete_access' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(flags.delete_access).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :delete_access, 'V', 0x00000004
    end
  end

  it 'has a CreateOptions field cleverly labeled create_options' do
    expect(packet.create_options).to be_a RubySMB::SMB1::BitField::CreateOptions
  end

  it 'tracks the offset to #name in #name_offset' do
    expect(packet.name_offset).to eq packet.name.abs_offset
  end

  it 'tracks the offset to #context in #context_offset' do
    expect(packet.context_offset).to eq packet.context.abs_offset
  end

  it 'tracks the length of #name in #name_length' do
    expect(packet.name_length).to eq packet.name.length
  end

  it 'tracks the length of #context in #context_length' do
    expect(packet.context_length).to eq packet.context.do_num_bytes
  end

  describe '#name' do
    it 'encodes any input into UTF-16LE' do
      packet.name = 'Hello'
      expect(packet.name.to_binary_s).to eq "H\x00e\x00l\x00l\x00o\x00"
    end
  end
end
