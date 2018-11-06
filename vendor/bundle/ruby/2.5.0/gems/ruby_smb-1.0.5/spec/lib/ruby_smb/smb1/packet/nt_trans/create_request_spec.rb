require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::NtTrans::CreateRequest do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a NtTrans Request ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::NtTrans::Request::ParameterBlock
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

    describe '#function' do
      it 'should be a CREATE' do
        expect(parameter_block.function).to eq RubySMB::SMB1::Packet::NtTrans::Subcommands::CREATE
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a Trans2 style DataBlock' do
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
      it { is_expected.to respond_to :flags }
      it { is_expected.to respond_to :root_directory_fid }
      it { is_expected.to respond_to :desired_access }
      it { is_expected.to respond_to :allocation_size }
      it { is_expected.to respond_to :ext_file_attribute }
      it { is_expected.to respond_to :share_access }
      it { is_expected.to respond_to :create_disposition }
      it { is_expected.to respond_to :create_options }
      it { is_expected.to respond_to :security_descriptor_length }
      it { is_expected.to respond_to :ea_length }
      it { is_expected.to respond_to :impersonation_level }
      it { is_expected.to respond_to :security_flags }
      it { is_expected.to respond_to :name }

      describe '#desired_access' do
        it 'should be a DirectoryAccessMask when the file is a directory' do
          parameters.ext_file_attribute.directory = 1
          access_mask = parameters.desired_access.send(:current_choice)
          expect(access_mask.class).to eq RubySMB::SMB1::BitField::DirectoryAccessMask
        end

        it 'should be a FileAccessMask when the file is not a directory' do
          parameters.ext_file_attribute.directory = 0
          access_mask = parameters.desired_access.send(:current_choice)
          expect(access_mask.class).to eq RubySMB::SMB1::BitField::FileAccessMask
        end
      end

      describe '#ext_file_attribute' do
        it 'is a SMB Extended File Attributes struct' do
          expect(parameters.ext_file_attribute).to be_a RubySMB::SMB1::BitField::SmbExtFileAttributes
        end
      end

      describe '#share_access' do
        it 'is a ShareAcess bitfield' do
          expect(parameters.share_access).to be_a RubySMB::SMB1::BitField::ShareAccess
        end
      end

      describe '#create_options' do
        it 'is a CreateOptions bit field' do
          expect(parameters.create_options).to be_a RubySMB::SMB1::BitField::CreateOptions
        end
      end

      describe '#flags' do
        subject(:flags) { parameters.flags }

        it { is_expected.to respond_to :open_target_dir }
        it { is_expected.to respond_to :request_opbatch }
        it { is_expected.to respond_to :request_oplock }

        describe '#open_target_dir' do
          it 'is a 1-bit flag' do
            expect(flags.open_target_dir).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :open_target_dir, 'V', 0x00000008
        end

        describe '#request_opbatch' do
          it 'is a 1-bit flag' do
            expect(flags.request_opbatch).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :request_opbatch, 'V', 0x00000004
        end

        describe '#request_oplock' do
          it 'is a 1-bit flag' do
            expect(flags.request_oplock).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :request_oplock, 'V', 0x00000002
        end
      end

      describe '#security_flags' do
        subject(:sec_flags) { parameters.security_flags }

        it { is_expected.to respond_to :effective_only }
        it { is_expected.to respond_to :context_tracking }

        describe '#effective_only' do
          it 'is a 1-bit flag' do
            expect(sec_flags.effective_only).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :effective_only, 'C', 0x02
        end

        describe '#context_tracking' do
          it 'is a 1-bit flag' do
            expect(sec_flags.context_tracking).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :context_tracking, 'C', 0x01
        end
      end
    end

    describe '#trans2_data' do
      subject(:data) { data_block.trans2_data }

      it { is_expected.to respond_to :security_descriptor }
      it { is_expected.to respond_to :extended_attributes }

      describe '#security_descriptor' do
        it 'is a Security Descriptor struct' do
          expect(data.security_descriptor).to be_a RubySMB::Field::SecurityDescriptor
        end
      end

      describe '#extended_attributes' do
        it 'is a FileFullEAInfo struct' do
          expect(data.extended_attributes).to be_a RubySMB::Fscc::FileFullEaInfo
        end
      end
    end
  end
end
