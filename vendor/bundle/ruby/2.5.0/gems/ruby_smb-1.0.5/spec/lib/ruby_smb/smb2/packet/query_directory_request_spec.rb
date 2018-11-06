require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::QueryDirectoryRequest do
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

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  it 'should have a structure size of 33' do
    expect(packet.structure_size).to eq 33
  end

  describe '#flags' do
    subject(:flags) { packet.flags }

    describe '#restart_scans' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(flags.restart_scans).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :restart_scans, 'C', 0x01
    end

    describe '#return_single' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(flags.return_single).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :return_single, 'C', 0x02
    end

    describe '#index_specified' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(flags.index_specified).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :index_specified, 'C', 0x04
    end

    describe '#reopen' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(flags.reopen).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :reopen, 'C', 0x10
    end
  end

  it 'has an SMB2 FILEID field' do
    expect(packet.file_id).to be_a RubySMB::Field::Smb2Fileid
  end

  it 'has an offset pointer to the name field' do
    expect(packet.name_offset).to eq packet.name.abs_offset
  end

  it 'has a length value for the name field' do
    expect(packet.name_length).to eq packet.name.do_num_bytes
  end
end
