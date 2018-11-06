require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileNamesInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_NAMES_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :next_offset }
  it { should respond_to :file_index }
  it { should respond_to :file_name_length }
  it { should respond_to :file_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
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
