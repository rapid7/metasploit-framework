RSpec.describe Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :name_type }
  it { is_expected.to respond_to :count_of_components }
  it { is_expected.to respond_to :realm }
  it { is_expected.to respond_to :components }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a BinData::Record' do
    expect(object).to be_a BinData::Record
  end

  describe '#name_time' do
    it 'is a Uint32' do
      expect(object.name_type).to be_a BinData::Uint32be
    end
  end

  describe '#count_of_components' do
    it 'is a Uint32' do
      expect(object.count_of_components).to be_a BinData::Uint32be
    end
  end

  describe '#realm' do
    it 'is a Krb5CcacheData' do
      expect(object.realm).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheData
    end
  end

  describe '#components' do
    it 'is a Array' do
      expect(object.components).to be_a BinData::Array
    end
  end

  it 'reads its own binary representation and outputs the same value' do
    value = described_class.new(
      name_type: 1,
      realm: 'MSFTEST',
      components: [ 'FOO', 'BAR' ]
    )
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end
end
