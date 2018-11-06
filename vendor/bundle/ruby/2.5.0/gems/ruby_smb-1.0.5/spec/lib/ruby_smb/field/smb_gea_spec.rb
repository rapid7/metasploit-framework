RSpec.describe RubySMB::Field::SmbGea do
  subject(:gea) { described_class.new }

  it { is_expected.to respond_to :attribute_name_length }
  it { is_expected.to respond_to :attribute_name }
  it { is_expected.to respond_to :null_pad }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#attribute_name_length' do
    it 'reflects the size of the attribute_name field' do
      gea.attribute_name = 'TEST'
      expect(gea.attribute_name_length).to eq 4
    end
  end

  it 'always has a null pad at the end' do
    expect(gea.null_pad).to eq 0x00
  end
end
