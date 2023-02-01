RSpec.describe Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheEpoch do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :epoch }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a BinData::Primitive' do
    expect(object).to be_a BinData::Primitive
  end

  describe '#epoch' do
    it 'is a Uint32' do
      expect(object.epoch).to be_a BinData::Uint32be
    end
  end

  describe '#assign' do
    it 'assigns a Time value correctly' do
      time = Time.now.round
      expect(object).to receive(:set).at_least(:once).with(time).and_call_original
      expect(object).to receive(:epoch=).at_least(:once).with(time.to_i).and_call_original
      object.assign(time)
      expect(object.to_binary_s).to eq [time.to_i].pack('N')
    end
  end

  describe '#get' do
    it 'returns a Time value' do
      expect(object.get).to be_a Time
    end
  end

  describe '#to_binary_s' do
    it 'returns the correct packed representation' do
      expect(object.to_binary_s).to eq "\x00\x00\x00\x00".b
    end
  end

  it 'reads its own binary representation and outputs the same value' do
    value = described_class.new(Time.now)
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end
end
