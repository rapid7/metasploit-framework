RSpec.describe Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredentialAuthdata do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :ad_type }
  it { is_expected.to respond_to :data }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a BinData::Record' do
    expect(object).to be_a BinData::Record
  end

  describe '#ad_type' do
    it 'is a Uint16' do
      expect(object.ad_type).to be_a BinData::Uint16be
    end
  end

  describe '#data' do
    it 'is a Krb5CcacheData' do
      expect(object.data).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheData
    end
  end

  it 'reads its own binary representation and outputs the same value' do
    value = described_class.new(
      ad_type: 1,
      data: Random.new.bytes(10)
    )
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end
end
