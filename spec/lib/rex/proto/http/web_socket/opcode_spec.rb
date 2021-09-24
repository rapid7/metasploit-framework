RSpec.describe Rex::Proto::Http::WebSocket::Opcode do
  subject(:opcode) { Rex::Proto::Http::WebSocket::Opcode }

  it { is_expected.to respond_to :to_sym }

  describe '#to_sym' do
    it 'converts to a symbol name' do
      expect(opcode.to_sym).to be_a Symbol
    end
  end
end
