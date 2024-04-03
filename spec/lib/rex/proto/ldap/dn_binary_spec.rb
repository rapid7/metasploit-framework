require 'securerandom'

RSpec.describe Rex::Proto::LDAP::DnBinary do
  let(:dn) do
    'CN=User,CN=Users,DC=msf,DC=local'
  end

  let(:data) do
    'abc123'
  end

  let(:sample) do
    described_class.new(dn, data)
  end

  it 'encodes to the expected value' do
    expect(sample.encode).to eq('B:12:616263313233:CN=User,CN=Users,DC=msf,DC=local')
  end

  it 'encodes an empty value' do
    initial = described_class.new(dn, '')
    encoded = initial.encode
    expect(encoded).to eq('B:0::CN=User,CN=Users,DC=msf,DC=local')
    decoded = described_class.decode(encoded)
    expect(decoded.data).to eq('')
  end

  it 'throws exception with completely wrong format' do
    expect { described_class.decode('definitely not a DN string') }.to raise_error(ArgumentError)
  end

  it 'throws exception without DN' do
    expect { described_class.decode('B:12:616263313233') }.to raise_error(ArgumentError)
  end

  it 'throws exception on odd number of hex chars' do
    expect { described_class.decode('B:11:61626331323:the_dn') }.to raise_error(ArgumentError)
  end

  it 'throws exception on inconsistent number of hex chars' do
    expect { described_class.decode('B:12:626331323:the_dn') }.to raise_error(ArgumentError)
  end

  it 'reversibly decodes a random value' do
    data = SecureRandom.bytes((SecureRandom.rand * 100).to_i + 1)
    initial = described_class.new(dn, data)
    encoded = initial.encode
    decoded = described_class.decode(encoded)
    expect(decoded.dn).to eq(initial.dn)
    expect(decoded.data).to eq(initial.data)
  end
end
