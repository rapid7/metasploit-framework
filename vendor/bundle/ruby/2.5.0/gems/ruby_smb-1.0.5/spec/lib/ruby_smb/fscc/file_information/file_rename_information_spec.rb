require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileRenameInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_ID_FULL_DIRECTORY_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :replace_if_exists }
  it { should respond_to :reserved }
  it { should respond_to :root_directory }
  it { should respond_to :file_name_length }
  it { should respond_to :file_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'reading in from a blob' do
    it 'uses the file_name_length to know when to stop reading' do
      name = 'Hello_world.txt'
      struct.file_name = name
      blob = struct.to_binary_s
      blob << 'AAAA'
      new_from_blob = described_class.read(blob)
      expect(new_from_blob.file_name).to eq name
    end
  end

  describe '#replace_if_exists' do
    it 'is a 8-bit field' do
      expect(struct.replace_if_exists).to be_a BinData::Uint8
    end
  end

  describe '#reserved' do
    context 'with SMB1' do
      it 'is a 3-bytes field' do
        allow(struct).to receive(:get_smb_version).and_return 1
        expect(struct.reserved.do_num_bytes).to eq 3
      end
    end

    context 'with SMB2' do
      it 'is a 7-bytes field' do
        allow(struct).to receive(:get_smb_version).and_return 2
        expect(struct.reserved.do_num_bytes).to eq 7
      end
    end
  end

  describe '#root_directory' do
    context 'with SMB1' do
      before :example do
        allow(struct).to receive(:get_smb_version).and_return 1
      end

      it 'is a 4-bytes field' do
        expect(struct.root_directory.do_num_bytes).to eq 4
      end

      it 'should have a default value of 0' do
        expect(struct.root_directory).to eq 0
      end
    end

    context 'with SMB2' do
      before :example do
        allow(struct).to receive(:get_smb_version).and_return 2
      end

      it 'is a 8-bytes field' do
        expect(struct.root_directory.do_num_bytes).to eq 8
      end

      it 'should have a default value of 0' do
        expect(struct.root_directory).to eq 0
      end
    end

  end

  describe '#file_name_length' do
    it 'is a 32-bit field' do
      expect(struct.file_name_length).to be_a BinData::Uint32le
    end

    it 'should have a default value of 0' do
      expect(struct.file_name_length).to eq 0
    end

    it 'tracks the length of the file_name field' do
      struct.file_name = 'Hello.txt'
      expect(struct.file_name_length).to eq struct.file_name.do_num_bytes
    end
  end

  describe '#file_name' do
    it 'is a string field' do
      expect(struct.file_name).to be_a BinData::String
    end
  end

  describe '#get_smb_version' do
    it 'is a recurssive method' do
      parent = double('parent object')
      allow(struct).to receive(:parent).and_return(parent)
      expect(struct).to receive(:respond_to?).and_return(false).twice.ordered
      expect(parent).to receive(:respond_to?).and_return(true).once.ordered
      struct.get_smb_version
    end

    it 'returns version 1 if smb_header structure is found in parents' do
      allow(struct).to receive(:respond_to?).with(:smb_header).and_return(true)
      expect(struct.get_smb_version).to eq 1
    end

    it 'returns version 2 if smb2_header structure is found in parents' do
      allow(struct).to receive(:respond_to?).with(:smb_header).and_return(false)
      allow(struct).to receive(:respond_to?).with(:smb2_header).and_return(true)
      expect(struct.get_smb_version).to eq 2
    end

    it 'returns version 1 if no header structure is found in parents' do
      allow(struct).to receive(:parent)
      allow(struct).to receive(:respond_to?).with(:smb_header).and_return(false)
      allow(struct).to receive(:respond_to?).with(:smb2_header).and_return(false)
      expect(struct.get_smb_version).to eq 1
    end
  end
end
