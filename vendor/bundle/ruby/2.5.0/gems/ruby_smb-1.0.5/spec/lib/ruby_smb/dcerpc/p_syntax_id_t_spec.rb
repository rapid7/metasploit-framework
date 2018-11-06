RSpec.describe RubySMB::Dcerpc::PSyntaxIdT do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :if_uuid }
  it { is_expected.to respond_to :if_ver_major }
  it { is_expected.to respond_to :if_ver_minor }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#if_uuid' do
    it 'is a Uuid' do
      expect(packet.if_uuid).to be_a RubySMB::Dcerpc::Uuid
    end
  end

  describe '#if_ver_major' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.if_ver_major).to be_a BinData::Uint16le
    end
  end

  describe '#if_ver_minor' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.if_ver_minor).to be_a BinData::Uint16le
    end
  end

end

