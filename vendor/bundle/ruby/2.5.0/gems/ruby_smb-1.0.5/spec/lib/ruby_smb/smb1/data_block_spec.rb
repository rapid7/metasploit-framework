RSpec.describe RubySMB::SMB1::DataBlock do
  subject(:data_block) { described_class.new }

  let(:record_class) do
    Class.new(described_class) do
      int8  :field1
      int32 :field2
    end
  end

  it { is_expected.to respond_to :byte_count }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#byte_count' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(data_block.byte_count).to be_a BinData::Uint16le
    end

    it 'should equal the size of the rest of the block in bytes' do
      remaining_size = data_block.do_num_bytes - 2
      expect(data_block.byte_count).to eq remaining_size
    end
  end

  describe 'class method #calculate_byte_count' do
    it 'always returns 0' do
      expect(described_class.calculate_byte_count).to eq 0
    end
  end

  describe 'class method #data_fields' do
    it 'lists all the fields except #byte_count field' do
      expect(record_class.data_fields).to eq([:field1, :field2])
    end
  end

  describe '#calculate_byte_count' do
    it 'returns the expected expected packet size' do
      expect(record_class.new.calculate_byte_count).to eq(5)
    end

    it 'does not count disabled fields' do
      record_class.class_eval do
        int8  :field3, onlyif: -> { false }
      end
      expect(record_class.new.calculate_byte_count).to eq(5)
    end
  end

  describe '#field_enabled?' do
    it 'returns true when the field is enabled' do
      expect(record_class.new.field_enabled?(:field1)).to be true
    end

    it 'returns false when the field is disabled' do
      record_class.class_eval do
        int8  :field3, onlyif: -> { false }
      end
      expect(record_class.new.field_enabled?(:field3)).to be false
    end
  end

end
