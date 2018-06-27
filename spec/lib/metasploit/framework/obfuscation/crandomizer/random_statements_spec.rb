require 'spec_helper'
require 'metasploit/framework/obfuscation/crandomizer/random_statements'
require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::RandomStatements do

  let(:c_source_code) do
    %Q|
    int main() {
      const char* s = "hello world";
      return 0;
    }|
  end

  subject(:random_statements) do
    parser = Metasploit::Framework::Obfuscation::CRandomizer::Utility.parse(c_source_code)
    fake_function_size = rand(0..3)
    fake_function_collection = Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunctionCollection.new(fake_function_size)
    described_class.new(parser, fake_function_collection)
  end

  describe '#initialize' do
    it 'sets the parser' do
      expect(subject.parser.class).to eq(Metasm::C::Parser)
    end

    it 'sets the fake function collection object' do
      expect(subject.fake_function_collection.class).to eq(Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunctionCollection)
    end

    it 'sets the fake function list' do
      expect(subject.function_list).not_to be_empty
    end
  end

  describe '#get' do
    it 'returns an array' do
      expect(subject.get.class).to eq(Array)
    end
  end
end