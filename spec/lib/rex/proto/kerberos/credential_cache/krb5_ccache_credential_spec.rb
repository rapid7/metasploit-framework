RSpec.describe Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredential do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :client }
  it { is_expected.to respond_to :server }
  it { is_expected.to respond_to :keyblock }
  it { is_expected.to respond_to :authtime }
  it { is_expected.to respond_to :starttime }
  it { is_expected.to respond_to :endtime }
  it { is_expected.to respond_to :renew_till }
  it { is_expected.to respond_to :is_skey }
  it { is_expected.to respond_to :ticket_flags }
  it { is_expected.to respond_to :address_count }
  it { is_expected.to respond_to :addresses }
  it { is_expected.to respond_to :authdata_count }
  it { is_expected.to respond_to :authdatas }
  it { is_expected.to respond_to :ticket }
  it { is_expected.to respond_to :second_ticket }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a BinData::Record' do
    expect(object).to be_a BinData::Record
  end

  describe '#client' do
    it 'is a Krb5CcachePrincipal' do
      expect(object.client).to be_a Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal
    end
  end

  describe '#server' do
    it 'is a Krb5CcachePrincipal' do
      expect(object.server).to be_a Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal
    end
  end

  describe '#keyblock' do
    it 'is a Krb5CcachePrincipal' do
      expect(object.keyblock).to be_a Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredentialKeyblock
    end
  end

  describe '#authtime' do
    it 'is a Krb5CcacheEpoch' do
      expect(object.authtime).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheEpoch
    end
  end

  describe '#starttime' do
    it 'is a Krb5CcacheEpoch' do
      expect(object.starttime).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheEpoch
    end
  end

  describe '#endtime' do
    it 'is a Krb5CcacheEpoch' do
      expect(object.endtime).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheEpoch
    end
  end

  describe '#renew_till' do
    it 'is a Krb5CcacheEpoch' do
      expect(object.renew_till).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheEpoch
    end
  end

  describe '#is_skey' do
    it 'is a Krb5CcacheBool' do
      expect(object.is_skey).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheBool
    end
  end

  describe '#ticket_flags' do
    it 'is a Uint32' do
      expect(object.ticket_flags).to be_a BinData::Uint32be
    end
  end

  describe '#address_count' do
    it 'is a Uint32' do
      expect(object.address_count).to be_a BinData::Uint32be
    end
  end

  describe '#addresses' do
    it 'is a Array' do
      expect(object.addresses).to be_a BinData::Array
    end
  end

  describe '#authdata_count' do
    it 'is a Uint32' do
      expect(object.authdata_count).to be_a BinData::Uint32be
    end
  end

  describe '#authdatas' do
    it 'is a Array' do
      expect(object.authdatas).to be_a BinData::Array
    end
  end

  describe '#ticket' do
    it 'is a Krb5CcacheData' do
      expect(object.ticket).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheData
    end
  end

  describe '#second_ticket' do
    it 'is a Krb5CcacheData' do
      expect(object.ticket).to be_a Rex::Proto::Kerberos::CredentialCache::Primitive::Krb5CcacheData
    end
  end

  it 'reads its own binary representation and outputs the same value' do
    value = described_class.new(
      client: Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal.new,
      server: Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal.new,
      keyblock: Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredentialKeyblock.new,
      authtime: Time.now,
      starttime: Time.now,
      endtime: Time.now,
      renew_till: Time.now,
      is_skey: false,
      ticket_flags: 1,
      addresses: [
        Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredentialAddress.new(
          data: IPAddr.new('127.0.0.1')
        )
      ],
      authdatas: [
        Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredentialAuthdata.new
      ],
      ticket: Random.new.bytes(10),
      second_ticket: Random.new.bytes(10)
    )
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end
end
