RSpec.describe RubySMB::Field::SmbGeaList do
  subject(:list) { described_class.new }
  let(:gea1) {
    fea = RubySMB::Field::SmbGea.new
    fea.attribute_name = 'foo'
    fea
  }
  let(:gea2) {
    fea = RubySMB::Field::SmbGea.new
    fea.attribute_name = 'hello world'
    fea
  }

  it { is_expected.to respond_to :size_of_list }
  it { is_expected.to respond_to :gea_list }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#size_of_list' do
    it 'shows the size, in bytes, of the fea_list' do
      list.gea_list << gea1
      total_size = list.size_of_list.do_num_bytes + gea1.do_num_bytes
      expect(list.size_of_list).to eq total_size
    end

    it 'changes dynamically as new GEAs are added' do
      list.gea_list << gea1
      total_size = list.size_of_list.do_num_bytes + gea1.do_num_bytes
      expect(list.size_of_list).to eq total_size
      list.gea_list << gea2
      total_size += gea2.do_num_bytes
      expect(list.size_of_list).to eq total_size
    end
  end
end
