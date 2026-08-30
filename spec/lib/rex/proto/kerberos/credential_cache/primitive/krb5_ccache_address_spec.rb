RSpec.describe Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheAddress do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :data }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a Krb5CcacheData' do
    expect(object).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheData
  end
end

RSpec.describe Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheAddress4 do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :data }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a Krb5CcacheAddress' do
    expect(object).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheAddress
  end

  describe '#assign' do
    it 'assigns an IPv4 address correctly' do
      expect(object).to receive(:set).at_least(:once).and_call_original
      expect(object).to receive(:data=).at_least(:once).with("\x7f\x00\x00\x01".b).and_call_original
      object.assign(IPAddr.new('127.0.0.1'))
      expect(object.to_binary_s).to eq "\x00\x00\x00\x04\x7f\x00\x00\x01".b
    end

    it 'raises an exception when passed a IPv6 address' do
      expect { object.assign(IPAddr.new('::1')) }.to raise_error IPAddr::AddressFamilyError
    end
  end

  describe '#get' do
    it 'returns an IPv4 address' do
      expect(object.get).to be_a IPAddr
      expect(object.get.ipv4?).to be_truthy
    end
  end

  describe '#to_binary_s' do
    it 'returns the correct packed representation' do
      expect(object.to_binary_s).to eq "\x00\x00\x00\x04\x00\x00\x00\x00".b
    end
  end

  it 'reads its own binary representation and outputs the same address' do
    packet = described_class.new(
      IPAddr.new('127.0.0.1')
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

RSpec.describe Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheAddress6 do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :data }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a Krb5CcacheAddress' do
    expect(object).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheAddress
  end

  describe '#assign' do
    it 'assigns an IPv6 address correctly' do
      expect(object).to receive(:set).at_least(:once).and_call_original
      expect(object).to receive(:data=).at_least(:once).with("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01".b).and_call_original
      object.assign(IPAddr.new('::1'))
      expect(object.to_binary_s).to eq "\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01".b
    end

    it 'raises an exception when passed a IPv4 address' do
      expect { object.assign(IPAddr.new('127.0.0.1')) }.to raise_error IPAddr::AddressFamilyError
    end
  end

  describe '#get' do
    it 'returns an IPv6 address' do
      expect(object.get).to be_a IPAddr
      expect(object.get.ipv6?).to be_truthy
    end
  end

  describe '#to_binary_s' do
    it 'returns the correct packed representation' do
      expect(object.to_binary_s).to eq "\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".b
    end
  end

  it 'reads its own binary representation and outputs the same address' do
    value = described_class.new(IPAddr.new('::1'))
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end
end
