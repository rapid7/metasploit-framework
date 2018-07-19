require 'metasploit/framework/obfuscation/crandomizer/parser'
require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::Parser do
  let(:random_weight) do
    80
  end

  subject(:parser) do
    described_class.new(random_weight)
  end

  describe '#initialize' do
    it 'sets the random weight' do
      expect(subject.max_random_weight).to eq(random_weight)
    end
  end

  describe '#parse' do
    it 'returns a parser' do
      source_code = %Q|
      int main() {
        const char* s = "Hello World";
        return 0;
      }|

      expect(subject.parse(source_code).class).to eq(Metasm::C::Parser)
    end
  end
end