require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::Trans2::FindFirst2Request do
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
      expect(parameter_block.setup).to include RubySMB::SMB1::Packet::Trans2::Subcommands::FIND_FIRST2
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

      it { is_expected.to respond_to :search_attributes }
      it { is_expected.to respond_to :search_count }
      it { is_expected.to respond_to :flags }
      it { is_expected.to respond_to :information_level }
      it { is_expected.to respond_to :storage_type }
      it { is_expected.to respond_to :filename }

      describe '#search_attributes' do
        it 'is a smb_file_attributes_field' do
          expect(parameters.search_attributes).to be_a RubySMB::SMB1::BitField::SmbFileAttributes
        end
      end

      describe '#flags' do
        subject(:flags) { parameters.flags }

        it { is_expected.to respond_to :backup }
        it { is_expected.to respond_to :continue }
        it { is_expected.to respond_to :resume_keys }
        it { is_expected.to respond_to :close_eos }
        it { is_expected.to respond_to :close }

        describe 'close' do
          it 'should be a 1-bit field per the SMB spec' do
            expect(flags.close).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :close, 'v', 0x0001
        end

        describe 'close_eos' do
          it 'should be a 1-bit field per the SMB spec' do
            expect(flags.close_eos).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :close_eos, 'v', 0x0002
        end

        describe 'resume_keys' do
          it 'should be a 1-bit field per the SMB spec' do
            expect(flags.resume_keys).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :resume_keys, 'v', 0x0004
        end

        describe 'continue' do
          it 'should be a 1-bit field per the SMB spec' do
            expect(flags.continue).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :continue, 'v', 0x0008
        end

        describe 'backup' do
          it 'should be a 1-bit field per the SMB spec' do
            expect(flags.backup).to be_a BinData::Bit1
          end

          it_behaves_like 'bit field with one flag set', :backup, 'v', 0x0010
        end
      end

      describe '#filename' do
        let(:name) { 'hello.txt' }

        before :example do
          parameters.filename = name
        end

        context 'when unicode flag is set' do
          before :example do
            packet.smb_header.flags2.unicode = 1
          end

          it 'is terminated with unicode null-termination character' do
            expect(parameters.filename.to_binary_s).to end_with("\x00\x00")
          end

          it 'is UTF-16LE encoded' do
            expect(parameters.filename.encoding.name).to eq 'UTF-16LE'
          end
        end

        context 'when unicode flag is not set' do
          before :example do
            packet.smb_header.flags2.unicode = 0
          end

          it 'is terminated with ASCII null-termination character' do
            expect(parameters.filename.to_binary_s).to end_with("\x00")
          end

          it 'is ASCII-8BIT encoded' do
            expect(parameters.filename.encoding.name).to eq 'ASCII-8BIT'
          end
        end
      end
    end

    describe '#trans2_data' do
      subject(:data) { data_block.trans2_data }

      it { is_expected.to respond_to :extended_attribute_list }

      describe '#extended_attribute_list' do
        it 'is an smb_gea_list' do
          expect(data.extended_attribute_list).to be_a RubySMB::Field::SmbGeaList
        end

        it 'only exists if the information level is SMB_INFO_QUERY_EAS_FROM_LIST' do
          data_block.trans2_parameters.information_level =
            RubySMB::SMB1::Packet::Trans2::FindInformationLevel::SMB_INFO_QUERY_EAS_FROM_LIST
          expect(data.do_num_bytes).to eq RubySMB::Field::SmbGeaList.new.do_num_bytes
        end

        it 'does not exist if the information level is SMB_INFO_STANDARD' do
          data_block.trans2_parameters.information_level =
            RubySMB::SMB1::Packet::Trans2::FindInformationLevel::SMB_INFO_STANDARD
          expect(data.do_num_bytes).to eq 0
        end
      end
    end
  end
end
