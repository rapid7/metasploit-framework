RSpec.describe Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheBool do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :data }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a BinData::Primitive' do
    expect(object).to be_a BinData::Primitive
  end

  describe '#data' do
    it 'is a Uint8' do
      expect(object.data).to be_a BinData::Uint8
    end
  end

  describe '#get' do
    it 'returns a boolean value' do
      expect(object.get).to be_a FalseClass
    end
  end

  describe '#assign' do
    it 'assigns a boolean value correctly' do
      expect(object).to receive(:set).at_least(:once).with(true).and_call_original
      expect(object).to receive(:data=).at_least(:once).with(1).and_call_original
      object.assign(true)
      expect(object.to_binary_s).to eq "\x01".b
    end
  end

  describe '#to_binary_s' do
    it 'returns the correct packed representation' do
      expect(object.to_binary_s).to eq "\x00".b
    end
  end

  it 'reads its own binary representation and outputs the same value' do
    value = described_class.new(true)
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end
end
