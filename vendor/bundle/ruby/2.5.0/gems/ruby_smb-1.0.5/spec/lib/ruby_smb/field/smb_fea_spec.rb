RSpec.describe RubySMB::Field::SmbFea do
  subject(:fea) { described_class.new }

  it { is_expected.to respond_to :ea_flag }
  it { is_expected.to respond_to :attribute_name_length }
  it { is_expected.to respond_to :attribute_value_length }
  it { is_expected.to respond_to :attribute_name }
  it { is_expected.to respond_to :attribute_value }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#attribute_name_length' do
    it 'reflects the size of the attribute_name field' do
      fea.attribute_name = 'TEST'
      expect(fea.attribute_name_length).to eq 4
    end
  end

  describe '#attribute_value_length' do
    it 'reflects the size of the attribute_value field' do
      fea.attribute_value = 'TEST'
      expect(fea.attribute_value_length).to eq 4
    end
  end
end
