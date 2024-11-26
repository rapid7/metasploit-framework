RSpec.describe Rex::Proto::Thrift::ThriftHeader do
  let(:value) { { version: 0x8001, message_type: 1, method_name: '', sequence_id: 1 } }
  let(:binary_s) { "\x80\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01".b }
  subject(:instance) { described_class.new }

  it { should respond_to :version }
  it { should respond_to :message_type }
  it { should respond_to :method_name }
  it { should respond_to :sequence_id }

  it 'is big endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'tracks the version in a Uint16 field' do
    expect(instance.version).to be_a BinData::Uint16be
  end

  it 'tracks the message type in a ThriftMessageType field' do
    expect(instance.message_type).to be_a Rex::Proto::Thrift::ThriftMessageType
  end

  it 'tracks the method name in a ThriftString field' do
    expect(instance.method_name).to be_a Rex::Proto::Thrift::ThriftString
  end

  it 'tracks the sequence ID in a Uint32 field' do
    expect(instance.sequence_id).to be_a BinData::Uint32be
  end

  it 'sets the version correctly by default' do
    expect(instance.version).to eq 0x8001
  end

  describe '#to_binary_s' do
    it 'should correctly encode' do
      expect(described_class.new(value).to_binary_s).to eq binary_s
    end
  end

  describe '.read' do
    it 'should correctly decode' do
      expect(described_class.read(binary_s)).to eq value
    end
  end
end
