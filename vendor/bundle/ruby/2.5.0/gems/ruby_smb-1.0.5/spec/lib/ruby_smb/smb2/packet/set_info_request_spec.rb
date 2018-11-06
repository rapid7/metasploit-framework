require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::SetInfoRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :info_type }
  it { is_expected.to respond_to :file_info_class }
  it { is_expected.to respond_to :buffer_length }
  it { is_expected.to respond_to :buffer_offset }
  it { is_expected.to respond_to :reserved }
  it { is_expected.to respond_to :additional_information }
  it { is_expected.to respond_to :file_id }
  it { is_expected.to respond_to :buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB2 Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_INFO' do
      expect(header.command).to eq RubySMB::SMB2::Commands::SET_INFO
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#structure_size' do
    it 'is a 16-bit field' do
      expect(packet.structure_size).to be_a BinData::Uint16le
    end

    it 'has a default value of 33' do
      expect(packet.structure_size).to eq 33
    end
  end

  describe '#info_type' do
    it 'is a 8-bit field' do
      expect(packet.info_type).to be_a BinData::Uint8
    end

   it 'has a default value of SMB2_0_INFO_FILE' do
      expect(packet.info_type).to eq RubySMB::SMB2::InfoType::SMB2_0_INFO_FILE
    end
  end

  describe '#file_info_class' do
    it 'is a 8-bit field' do
      expect(packet.file_info_class).to be_a BinData::Uint8
    end
  end

  describe '#buffer_length' do
    it 'is a 32-bit field' do
      expect(packet.buffer_length).to be_a BinData::Uint32le
    end

    it 'is set to the buffer size' do
      packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_FULL_DIRECTORY_INFORMATION
      expect(packet.buffer_length).to eq packet.buffer.do_num_bytes
    end
  end

  describe '#buffer_offset' do
    it 'is a 16-bit field' do
      expect(packet.buffer_offset).to be_a BinData::Uint16le
    end

    it 'is set to the buffer size' do
      packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_FULL_DIRECTORY_INFORMATION
      expect(packet.buffer_offset).to eq packet.buffer.abs_offset
    end
  end

  describe '#additional_information' do
    subject(:additional_information) { packet.additional_information }

    it { is_expected.to respond_to :scope_security_information }
    it { is_expected.to respond_to :attribute_security_information }
    it { is_expected.to respond_to :label_security_information }
    it { is_expected.to respond_to :sacl_security_information }
    it { is_expected.to respond_to :dacl_security_information }
    it { is_expected.to respond_to :group_security_information }
    it { is_expected.to respond_to :owner_security_information }
    it { is_expected.to respond_to :backup_security_information }

    describe '#scope_security_information' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(additional_information.scope_security_information).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :scope_security_information, 'V', 0x00000040
    end

    describe '#attribute_security_information' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(additional_information.attribute_security_information).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :attribute_security_information, 'V', 0x00000020
    end

    describe '#label_security_information' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(additional_information.label_security_information).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :label_security_information, 'V', 0x00000010
    end

    describe '#sacl_security_information' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(additional_information.sacl_security_information).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :sacl_security_information, 'V', 0x00000008
    end

    describe '#dacl_security_information' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(additional_information.dacl_security_information).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :dacl_security_information, 'V', 0x00000004
    end

    describe '#group_security_information' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(additional_information.group_security_information).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :group_security_information, 'V', 0x00000002
    end

    describe '#owner_security_information' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(additional_information.owner_security_information).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :owner_security_information, 'V', 0x00000001
    end

    describe '#backup_security_information' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(additional_information.backup_security_information).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :backup_security_information, 'V', 0x00010000
    end
  end

  describe '#file_id' do
    it 'is a Smb2Fileid field' do
      expect(packet.file_id).to be_a RubySMB::Field::Smb2Fileid
    end
  end

  describe '#buffer' do
    context 'when file_info_class is set' do
      it 'is set to a FileDirectoryInformation class with the FILE_DIRECTORY_INFORMATION code' do
        packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_DIRECTORY_INFORMATION
        expect(packet.buffer).to eq RubySMB::Fscc::FileInformation::FileDirectoryInformation.new
      end
      it 'is set to a FileFullDirectoryInformation class with the FILE_FULL_DIRECTORY_INFORMATION code' do
        packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_FULL_DIRECTORY_INFORMATION
        expect(packet.buffer).to eq RubySMB::Fscc::FileInformation::FileFullDirectoryInformation.new
      end
      it 'is set to a FileDispositionInformation class with the FILE_DISPOSITION_INFORMATION code' do
        packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_DISPOSITION_INFORMATION
        expect(packet.buffer).to eq RubySMB::Fscc::FileInformation::FileDispositionInformation.new
      end
      it 'is set to a FileIdFullDirectoryInformation class with the FILE_ID_FULL_DIRECTORY_INFORMATION code' do
        packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_ID_FULL_DIRECTORY_INFORMATION
        expect(packet.buffer).to eq RubySMB::Fscc::FileInformation::FileIdFullDirectoryInformation.new
      end
      it 'is set to a FileBothDirectoryInformation class with the FILE_BOTH_DIRECTORY_INFORMATION code' do
        packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_BOTH_DIRECTORY_INFORMATION
        expect(packet.buffer).to eq RubySMB::Fscc::FileInformation::FileBothDirectoryInformation.new
      end
      it 'is set to a FileIdBothDirectoryInformation class with the FILE_ID_BOTH_DIRECTORY_INFORMATION code' do
        packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_ID_BOTH_DIRECTORY_INFORMATION
        expect(packet.buffer).to eq RubySMB::Fscc::FileInformation::FileIdBothDirectoryInformation.new
      end
      it 'is set to a FileNamesInformation class with the FILE_NAMES_INFORMATION code' do
        packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_NAMES_INFORMATION
        expect(packet.buffer).to eq RubySMB::Fscc::FileInformation::FileNamesInformation.new
      end
      it 'is set to a FileRenameInformation class with the FILE_RENAME_INFORMATION code' do
        packet.file_info_class = RubySMB::Fscc::FileInformation::FILE_RENAME_INFORMATION
        expect(packet.buffer).to eq RubySMB::Fscc::FileInformation::FileRenameInformation.new
      end
    end
  end

end
