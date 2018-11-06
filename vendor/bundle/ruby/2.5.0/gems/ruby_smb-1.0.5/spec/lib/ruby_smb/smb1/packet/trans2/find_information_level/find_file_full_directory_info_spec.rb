RSpec.describe RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::SMB1::Packet::Trans2::FindInformationLevel::SMB_FIND_FILE_FULL_DIRECTORY_INFO
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
  it { should respond_to :ext_file_attributes }
  it { should respond_to :file_name_length }
  it { should respond_to :ea_size }
  it { should respond_to :file_name }
  it { should respond_to :unicode }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#next_offset' do
    it 'is a 32-bit field' do
      expect(struct.next_offset).to be_a BinData::Uint32le
    end
  end

  describe '#file_index' do
    it 'is a 32-bit field' do
      expect(struct.file_index).to be_a BinData::Uint32le
    end
  end

  describe '#create_time' do
    it 'is a Filetime field' do
      expect(struct.create_time).to be_a RubySMB::Field::FileTime
    end
  end

  describe '#last_access' do
    it 'is a Filetime field' do
      expect(struct.last_access).to be_a RubySMB::Field::FileTime
    end
  end

  describe '#last_write' do
    it 'is a Filetime field' do
      expect(struct.last_write).to be_a RubySMB::Field::FileTime
    end
  end

  describe '#last_change' do
    it 'is a Filetime field' do
      expect(struct.last_change).to be_a RubySMB::Field::FileTime
    end
  end

  describe '#end_of_file' do
    it 'is a 64-bit field' do
      expect(struct.end_of_file).to be_a BinData::Uint64le
    end
  end

  describe '#ext_file_attributes' do
    it 'contains the extended file attributes of the file' do
      expect(struct.ext_file_attributes).to be_a RubySMB::SMB1::BitField::SmbExtFileAttributes
    end
  end

  describe '#file_name_length' do
    it 'is a 32-bit field' do
      expect(struct.file_name_length).to be_a BinData::Uint32le
    end

    it 'tracks the length of the file_name field including the null-terminating character when unicode is not set' do
      filename = "Hello.txt"
      struct.file_name = filename
      expect(struct.file_name_length).to eq (filename.bytes.size + 1)
    end

    it 'tracks the length of the file_name field without null-terminating characters when unicode is set' do
      filename = "Hello.txt"
      struct.unicode = true
      struct.file_name = filename
      expect(struct.file_name_length).to eq (filename.encode('UTF-16LE').bytes.size)
    end
  end

  describe '#ea_size' do
    it 'is a 32-bit field' do
      expect(struct.ea_size).to be_a BinData::Uint32le
    end
  end

  describe '#file_name' do
    let(:filename) { "Hello.txt" }

    before :example do
      struct.file_name = filename
    end

    it 'is an unicode string field when unicode attribute is set to true' do
      struct.unicode = true
      expect(struct.file_name.encoding.name).to eq 'UTF-16LE'
    end

    it 'is an ASCII-8BIT field when unicode attribute is set to false' do
      expect(struct.file_name.encoding.name).to eq 'ASCII-8BIT'
    end

    it 'is null-terminated when unicode attribute is set to false' do
      expect(struct.file_name.to_binary_s).to eq "#{filename}\x00"
    end
  end

  describe '#unicode' do
    it 'is set to false by default' do
      expect(struct.unicode).to be false
    end
  end

end

