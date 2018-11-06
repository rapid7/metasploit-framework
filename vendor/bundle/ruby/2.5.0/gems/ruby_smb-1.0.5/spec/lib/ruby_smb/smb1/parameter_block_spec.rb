RSpec.describe RubySMB::SMB1::ParameterBlock do
  subject(:parameter_block) { described_class.new }

  it { is_expected.to respond_to :word_count }

  describe 'byte_count' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(parameter_block.word_count).to be_a BinData::Uint8
    end

    it 'should equal the size of the rest of the block in words' do
      remaining_size = ((parameter_block.do_num_bytes - 1) / 2).ceil
      expect(parameter_block.word_count).to eq remaining_size
    end
  end

  describe 'class method #calculate_word_count' do
    it 'always returns 0' do
      expect(described_class.calculate_word_count).to eq 0
    end
  end

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
end
