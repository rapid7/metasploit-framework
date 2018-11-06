RSpec.describe RubySMB::Field::SmbFeaList do
  subject(:list) { described_class.new }
  let(:fea1) {
    fea = RubySMB::Field::SmbFea.new
    fea.attribute_name  = 'foo'
    fea.attribute_value = 'bar'
    fea
  }
  let(:fea2) {
    fea = RubySMB::Field::SmbFea.new
    fea.attribute_name  = 'hello world'
    fea.attribute_value = 'this is a test'
    fea
  }

  it { is_expected.to respond_to :size_of_list }
  it { is_expected.to respond_to :fea_list }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#size_of_list' do
    it 'shows the size, in bytes, of the fea_list' do
      list.fea_list << fea1
      expect(list.size_of_list).to eq fea1.do_num_bytes
    end

    it 'changes dynamically as new FEAs are added' do
      list.fea_list << fea1
      expect(list.size_of_list).to eq fea1.do_num_bytes
      list.fea_list << fea2
      expect(list.size_of_list).to eq(fea1.do_num_bytes + fea2.do_num_bytes)
    end
  end
end
