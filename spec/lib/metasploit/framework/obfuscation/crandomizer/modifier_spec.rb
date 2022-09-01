require 'metasploit/framework/obfuscation/crandomizer/parser'
require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::Modifier do
  subject(:modifier) do
    weight = 80

    source_code = %Q|
    int main() {
      int x = 0;
      return 0;
    }|

    p = Metasploit::Framework::Obfuscation::CRandomizer::Parser.new(weight)
    parser = p.parse(source_code)

    fake_function_size = rand(1..3)
    fake_function_collection = Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunctionCollection.new(fake_function_size)

    described_class.new(parser, fake_function_collection, weight)
  end

  describe '#get_fake_statement' do
    it 'returns an array' do
      expect(subject.send(:get_fake_statement).class).to eq(Array)
    end
  end

  describe '#feeling_lucky' do
    it 'returns an boolean' do
      expect(subject.send(:feeling_lucky?).class).to eq(TrueClass).or eq(FalseClass)
    end
  end
end