RSpec.describe RubySMB::Field::Smb2Fileid do
  subject(:fea) { described_class.new }

  it { is_expected.to respond_to :persistent }
  it { is_expected.to respond_to :volatile }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
end
