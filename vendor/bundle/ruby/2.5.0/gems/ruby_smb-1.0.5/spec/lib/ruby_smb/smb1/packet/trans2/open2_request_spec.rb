require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::Trans2::Open2Request do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
    end

    it 'should have the setup set to the OPEN2 subcommand' do
      expect(parameter_block.setup).to include RubySMB::SMB1::Packet::Trans2::Subcommands::OPEN2
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :name }
    it { is_expected.to respond_to :trans2_parameters }
    it { is_expected.to respond_to :trans2_data }

    it 'should keep #trans2_parameters 4-byte aligned' do
      expect(data_block.trans2_parameters.abs_offset % 4).to eq 0
    end

    it 'should keep #trans2_data 4-byte aligned' do
      expect(data_block.trans2_data.abs_offset % 4).to eq 0
    end

    describe '#trans2_parameters' do
      subject(:parameters) { data_block.trans2_parameters }

      it { is_expected.to respond_to :flags }
      it { is_expected.to respond_to :access_mode }
      it { is_expected.to respond_to :file_attributes }
      it { is_expected.to respond_to :creation_time }
      it { is_expected.to respond_to :open_mode }
      it { is_expected.to respond_to :allocation_size }
      it { is_expected.to respond_to :filename }

      describe '#flags' do
        it 'is an open2_flags field' do
          expect(parameters.flags).to be_a RubySMB::SMB1::BitField::Open2Flags
        end
      end

      describe '#access_mode' do
        it 'is an open2_access_mode field' do
          expect(parameters.access_mode).to be_a RubySMB::SMB1::BitField::Open2AccessMode
        end
      end

      describe '#file_attributes' do
        it 'is a smb_file_attributes field' do
          expect(parameters.file_attributes).to be_a RubySMB::SMB1::BitField::SmbFileAttributes
        end
      end

      describe '#creation_time' do
        it 'is a utime field' do
          expect(parameters.creation_time).to be_a RubySMB::Field::Utime
        end
      end

      describe '#open_mode' do
        it 'is an open2_open_mode field' do
          expect(parameters.open_mode).to be_a RubySMB::SMB1::BitField::Open2OpenMode
        end
      end
    end

    describe '#trans2_data' do
      subject(:data) { data_block.trans2_data }

      it { is_expected.to respond_to :extended_attribute_list }

      describe '#extended_attribute_list' do
        it 'is an smb_fea_list' do
          expect(data.extended_attribute_list).to be_a RubySMB::Field::SmbFeaList
        end
      end
    end
  end
end
