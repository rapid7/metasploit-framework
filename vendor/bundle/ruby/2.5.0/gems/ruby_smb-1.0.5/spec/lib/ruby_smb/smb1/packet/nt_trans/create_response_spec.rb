require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::NtTrans::CreateResponse do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a NTTrans Response ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::NtTrans::Response::ParameterBlock
    end

    describe 'parameter_count' do
      it 'is a count of bytes in the data_block trans2_parameters field' do
        expect(parameter_block.parameter_count).to eq packet.data_block.trans2_parameters.do_num_bytes
      end
    end

    describe 'parameter_offset' do
      it ' contains the absolute_offset to the data_block trans2_parameters field' do
        expect(parameter_block.parameter_offset).to eq packet.data_block.trans2_parameters.abs_offset
      end
    end

    describe 'data_count' do
      it 'is a count of bytes in the data_block trans2_data field' do
        expect(parameter_block.data_count).to eq packet.data_block.trans2_data.do_num_bytes
      end
    end

    describe 'data_offset' do
      it 'contains the absolute_offset to the data_block trans2_data field' do
        expect(parameter_block.data_offset).to eq packet.data_block.trans2_data.abs_offset
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    describe '#trans2_data' do
      it 'should be a 0-byte string' do
        expect(data_block.trans2_data.length).to eq 0
      end
    end

    describe '#trans2_parameters' do
      subject(:parameters) { data_block.trans2_parameters }

      it { is_expected.to respond_to :oplock_level }
      it { is_expected.to respond_to :fid }
      it { is_expected.to respond_to :create_action }
      it { is_expected.to respond_to :ea_error_offset }
      it { is_expected.to respond_to :creation_time }
      it { is_expected.to respond_to :last_access_time }
      it { is_expected.to respond_to :last_write_time }
      it { is_expected.to respond_to :last_change_time }
      it { is_expected.to respond_to :ext_file_attributes }
      it { is_expected.to respond_to :allocation_size }
      it { is_expected.to respond_to :end_of_file }
      it { is_expected.to respond_to :resource_type }
      it { is_expected.to respond_to :nmpipe_status }
      it { is_expected.to respond_to :directory }

      describe '#creation_time' do
        it 'is a FileTime field' do
          expect(parameters.creation_time).to be_a RubySMB::Field::FileTime
        end
      end

      describe '#last_access_time' do
        it 'is a FileTime field' do
          expect(parameters.last_access_time).to be_a RubySMB::Field::FileTime
        end
      end

      describe '#last_write_time' do
        it 'is a FileTime field' do
          expect(parameters.last_write_time).to be_a RubySMB::Field::FileTime
        end
      end

      describe '#last_change_time' do
        it 'is a FileTime field' do
          expect(parameters.last_change_time).to be_a RubySMB::Field::FileTime
        end
      end

      describe '#ext_file_attributes' do
        it 'is a SmbExtFileAttributes field' do
          expect(parameters.ext_file_attributes).to be_a RubySMB::SMB1::BitField::SmbExtFileAttributes
        end
      end

      describe '#nmpipe_status' do
        it 'is a SmbnmpipeStatus field' do
          expect(parameters.nmpipe_status).to be_a RubySMB::SMB1::BitField::SmbNmpipeStatus
        end
      end
    end
  end
end
