RSpec.describe RubySMB::SMB1::Packet::NtCreateAndxRequest do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NT_CREATE_ANDX' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NT_CREATE_ANDX
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
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
    it { is_expected.to respond_to :name_length }
    it { is_expected.to respond_to :flags }
    it { is_expected.to respond_to :root_directory_fid }
    it { is_expected.to respond_to :desired_access }
    it { is_expected.to respond_to :allocation_size }
    it { is_expected.to respond_to :ext_file_attributes }
    it { is_expected.to respond_to :share_access }
    it { is_expected.to respond_to :create_disposition }
    it { is_expected.to respond_to :create_options }
    it { is_expected.to respond_to :impersonation_level }
    it { is_expected.to respond_to :security_flags }

    describe '#andx_block' do
      it 'is a AndXBlock struct' do
        expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
      end
    end

    describe '#name_length' do
      it 'is updated according to the #file_name length' do
        file_name = 'test_name'
        packet.data_block.file_name = file_name
        expect(parameter_block.name_length).to eq(file_name.length)
      end
    end

    describe '#flags' do
      subject(:flags) { parameter_block.flags }

      it { is_expected.to respond_to :request_extended_response }
      it { is_expected.to respond_to :open_target_dir }
      it { is_expected.to respond_to :request_opbatch }
      it { is_expected.to respond_to :request_oplock }

      it 'is little endian' do
        expect(flags.get_parameter(:endian).endian).to eq :little
      end

      describe '#request_extended_response' do
        it 'is a 1-bit flag' do
          expect(flags.request_extended_response).to be_a BinData::Bit1
        end

        it_behaves_like 'bit field with one flag set', :request_extended_response, 'V', 0x00000010
      end

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

    describe '#desired_access' do
      it 'should be a DirectoryAccessMask when the file is a directory' do
        parameter_block.ext_file_attributes.directory = 1
        access_mask = parameter_block.desired_access.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::DirectoryAccessMask
      end

      it 'should be a FileAccessMask when the file is not a directory' do
        parameter_block.ext_file_attributes.directory = 0
        access_mask = parameter_block.desired_access.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::FileAccessMask
      end
    end

    describe '#ext_file_attributes' do
      it 'is a SmbExtFileAttributes bit-field' do
        expect(parameter_block.ext_file_attributes).to be_a RubySMB::SMB1::BitField::SmbExtFileAttributes
      end
    end

    describe '#share_access' do
      it 'is a ShareAccess bit-field' do
        expect(parameter_block.share_access).to be_a RubySMB::SMB1::BitField::ShareAccess
      end
    end

    describe '#create_options' do
      it 'is a CreateOptions bit-field' do
        expect(parameter_block.create_options).to be_a RubySMB::SMB1::BitField::CreateOptions
      end
    end

    describe '#security_flags' do
      it 'is a SecurityFlags bit-field' do
        expect(parameter_block.security_flags).to be_a RubySMB::SMB1::BitField::SecurityFlags
      end
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :file_name }
  end
end
