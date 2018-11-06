RSpec.describe RubySMB::SMB1::Packet::NtCreateAndxResponse do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NT_CREATE_ANDX' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NT_CREATE_ANDX
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::ParameterBlock
    end

    it 'is little endian' do
      expect(parameter_block.get_parameter(:endian).endian).to eq :little
    end

    it { is_expected.to respond_to :andx_block }
    it { is_expected.to respond_to :oplock_level }
    it { is_expected.to respond_to :fid }
    it { is_expected.to respond_to :create_disposition }
    it { is_expected.to respond_to :create_time }
    it { is_expected.to respond_to :last_access_time }
    it { is_expected.to respond_to :last_write_time }
    it { is_expected.to respond_to :last_change_time }
    it { is_expected.to respond_to :ext_file_attributes }
    it { is_expected.to respond_to :allocation_size }
    it { is_expected.to respond_to :end_of_file }
    it { is_expected.to respond_to :resource_type }
    it { is_expected.to respond_to :status_flags }
    it { is_expected.to respond_to :directory }
    it { is_expected.to respond_to :volume_guid }
    it { is_expected.to respond_to :file_id }
    it { is_expected.to respond_to :maximal_access_rights }
    it { is_expected.to respond_to :guest_maximal_access_rights }

    describe '#andx_block' do
      it 'is a AndXBlock struct' do
        expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
      end
    end

    describe '#create_time' do
      it 'is as a FileTime struct' do
        expect(parameter_block.create_time).to be_a RubySMB::Field::FileTime
      end
    end

    describe '#last_access_time' do
      it 'is as a FileTime struct' do
        expect(parameter_block.last_access_time).to be_a RubySMB::Field::FileTime
      end
    end

    describe '#last_write_time' do
      it 'is as a FileTime struct' do
        expect(parameter_block.last_write_time).to be_a RubySMB::Field::FileTime
      end
    end

    describe '#last_change_time' do
      it 'is as a FileTime struct' do
        expect(parameter_block.last_change_time).to be_a RubySMB::Field::FileTime
      end
    end

    describe '#ext_file_attributes' do
      it 'is a SmbExtFileAttributes bit-field' do
        expect(parameter_block.ext_file_attributes).to be_a RubySMB::SMB1::BitField::SmbExtFileAttributes
      end
    end

    describe '#volume_guid' do
      it 'has the correct length' do
        expect(parameter_block.volume_guid.length).to eq 16
      end
    end

    describe '#status_flag' do
      it 'should be a SmbNmpipeStatus when the ResourceType is BYTE_MODE_PIPE' do
        parameter_block.resource_type = RubySMB::SMB1::ResourceType::BYTE_MODE_PIPE
        access_mask = parameter_block.status_flags.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::SmbNmpipeStatus
      end

      it 'should be a SmbNmpipeStatus when the ResourceType is MESSAGE_MODE_PIPE' do
        parameter_block.resource_type = RubySMB::SMB1::ResourceType::MESSAGE_MODE_PIPE
        access_mask = parameter_block.status_flags.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::SmbNmpipeStatus
      end

      it 'should be a SmbNmpipeStatus when the ResourceType is DISK' do
        parameter_block.resource_type = RubySMB::SMB1::ResourceType::DISK
        access_mask = parameter_block.status_flags.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::FileStatusFlags
      end

      it 'should be a SmbNmpipeStatus when the ResourceType is BYTE_MODE_PIPE' do
        parameter_block.resource_type = RubySMB::SMB1::ResourceType::PRINTER
        expect(parameter_block.status_flags).to eq(0x0000)
      end
    end

    describe '#maximal_access_rights' do
      it 'should be a DirectoryAccessMask when the file is a directory' do
        parameter_block.ext_file_attributes.directory = 1
        access_mask = parameter_block.maximal_access_rights.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::DirectoryAccessMask
      end

      it 'should be a FileAccessMask when the file is not a directory' do
        parameter_block.ext_file_attributes.directory = 0
        access_mask = parameter_block.maximal_access_rights.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::FileAccessMask
      end
    end

    describe '#guest_maximal_access_rights' do
      it 'should be a DirectoryAccessMask when the file is a directory' do
        parameter_block.ext_file_attributes.directory = 1
        access_mask = parameter_block.guest_maximal_access_rights.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::DirectoryAccessMask
      end

      it 'should be a FileAccessMask when the file is not a directory' do
        parameter_block.ext_file_attributes.directory = 0
        access_mask = parameter_block.guest_maximal_access_rights.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::FileAccessMask
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it 'should be empty' do
      expect(data_block.byte_count).to eq(0)
    end
  end
end
