require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileFullDirectoryInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_FULL_DIRECTORY_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :next_offset }
  it { should respond_to :file_index }
  it { should respond_to :create_time }
  it { should respond_to :last_access }
  it { should respond_to :last_write }
  it { should respond_to :last_change }
  it { should respond_to :end_of_file }
  it { should respond_to :allocation_size }
  it { should respond_to :file_attributes }
  it { should respond_to :file_name_length }
  it { should respond_to :ea_size }
  it { should respond_to :file_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the creation time in a Filetime field' do
    expect(struct.create_time).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last access time in a Filetime field' do
    expect(struct.last_access).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last write time in a Filetime field' do
    expect(struct.last_write).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last modified time in a Filetime field' do
    expect(struct.last_change).to be_a RubySMB::Field::FileTime
  end

  it 'contains the file attributes of the file' do
    expect(struct.file_attributes).to be_a RubySMB::Fscc::FileAttributes
  end

  it 'tracks the length of the file_name field' do
    struct.file_name = 'Hello.txt'
    expect(struct.file_name_length).to eq struct.file_name.do_num_bytes
  end

  it 'automatically encodes the file name in UTF-16LE' do
    name = 'Hello_world.txt'
    struct.file_name = name
    expect(struct.file_name.force_encoding('utf-16le')).to eq name.encode('utf-16le')
  end

  describe 'reading in from a blob' do
    it 'uses the file_name_length to know when to stop reading' do
      name = 'Hello_world.txt'
      struct.file_name = name
      blob = struct.to_binary_s
      blob << 'AAAA'
      new_from_blob = described_class.read(blob)
      expect(new_from_blob.file_name.force_encoding('utf-16le')).to eq name.encode('utf-16le')
    end
  end
end
