require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::Trans2::Open2Response do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_TRANSACTION2' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard Trans2 ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a Trans2 DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::Packet::Trans2::DataBlock
    end

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

      it { is_expected.to respond_to :fid }
      it { is_expected.to respond_to :file_attributes }
      it { is_expected.to respond_to :creation_time }
      it { is_expected.to respond_to :access_mode }
      it { is_expected.to respond_to :resource_type }
      it { is_expected.to respond_to :nmpipe_status }
      it { is_expected.to respond_to :action_taken }
      it { is_expected.to respond_to :extended_attribute_offset }
      it { is_expected.to respond_to :extended_attribute_length }

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

      describe '#smb_nmpipe_status' do
        it 'is a Named Pipe Status field' do
          expect(parameters.nmpipe_status).to be_a RubySMB::SMB1::BitField::SmbNmpipeStatus
        end
      end

      describe '#action_taken' do
        subject(:action) { parameters.action_taken }

        it 'is 2-bytes' do
          expect(action.do_num_bytes).to eq 2
        end

        describe '#open_result' do
          it_behaves_like 'bit field with one flag set', :open_result, 'v', 0x0001
        end

        describe '#lock_status' do
          it_behaves_like 'bit field with one flag set', :lock_status, 'v', 0x8000
        end
      end
    end
  end
end
