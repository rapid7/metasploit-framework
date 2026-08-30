RSpec.describe Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredentialAddress do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :addrtype }
  it { is_expected.to respond_to :data }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a BinData::Record' do
    expect(object).to be_a BinData::Record
  end

  describe '#addrtype' do
    it 'is a Uint16' do
      expect(object.addrtype).to be_a BinData::Uint16be
    end
  end

  describe '#data' do
    it 'is a Choice' do
      expect(object.data).to be_a BinData::Choice
    end
  end

  it 'reads its own binary representation and outputs the same value' do
    value = described_class.new(
      addrtype: Rex::Proto::Kerberos::Model::AddressType::IPV4,
      data: IPAddr.new('127.0.0.1')
    )
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end

  it 'reads an unsupported address type as a string' do
    value = described_class.read("\xff\xff\x00\x00\x00\x00".b)
    # just a test value that isn't supported, see https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.3
    expect(value.addrtype).to eq 0xffff
    expect(value.data).to eq ''
  end
end
