RSpec.describe Rex::Proto::Http::WebSocket::Opcode do
  subject(:opcode) { Rex::Proto::Http::WebSocket::Opcode.new }
  let(:invalid_value) { 15 }

  it { is_expected.to respond_to :to_sym }

  describe '#initialize' do
    it 'fails when the opcode is invalid' do
      expect { described_class.new(invalid_value) }.to raise_error(BinData::ValidityError)
    end
  end

  describe '#name' do
    it 'looks up an opcode\'s name' do
      name = described_class.name(opcode.value)
      expect(name).to be_a Symbol
      expect(name).to eq opcode.to_sym
    end

    it 'returns nil for invalid opcodes' do
      expect(described_class.name(invalid_value)).to be_nil
    end
  end

  describe '#to_sym' do
    it 'converts to a symbol name' do
      expect(opcode.to_sym).to be_a Symbol
    end
  end
end
