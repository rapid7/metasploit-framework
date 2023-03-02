RSpec.describe Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheData do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :len }
  it { is_expected.to respond_to :data }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a BinData::Primitive' do
    expect(object).to be_a BinData::Primitive
  end

  describe '#len' do
    it 'is a Uint32' do
      expect(object.len).to be_a BinData::Uint32be
    end
  end

  describe '#data' do
    it 'is a String' do
      expect(object.data).to be_a BinData::String
    end
  end

  describe '#assign' do
    it 'assigns a String value correctly' do
      expect(object).to receive(:set).at_least(:once).with('test').and_call_original
      expect(object).to receive(:data=).at_least(:once).with('test').and_call_original
      object.assign('test')
      expect(object.to_binary_s).to eq "\x00\x00\x00\x04test".b
    end
  end

  describe '#get' do
    it 'returns a String value' do
      expect(object.get).to be_a String
    end
  end

  describe '#to_binary_s' do
    it 'returns the correct packed representation' do
      expect(object.to_binary_s).to eq "\x00\x00\x00\x00".b
    end
  end

  it 'reads its own binary representation and outputs the same value' do
    value = described_class.new('test')
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end
end
