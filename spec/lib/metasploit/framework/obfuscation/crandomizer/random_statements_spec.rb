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
    fake_function_size = rand(1..3)
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
      expect(subject.statements).not_to be_empty
    end
  end

  describe '#get' do
    it 'returns an array' do
      expect(subject.get.class).to eq(Array)
    end
  end

  describe '#make_func_arg_str' do
    it 'returns the argument string' do
      fake_function = subject.fake_function_collection.sample
      fake_function_name = fake_function.var.name
      fake_function_args = fake_function.var.type.args
      s = subject.send(:make_func_arg_str, fake_function_args)
      expect(s).to match(/\(.*\)/)
    end
  end

  describe '#make_func_declare_arg_str' do
    it 'returns the function declaration argument string' do
      fake_function = subject.fake_function_collection.sample
      fake_function_name = fake_function.var.name
      fake_function_args = fake_function.var.type.args
      s = subject.send(:make_func_declare_arg_str, fake_function_args)
      expect(s).to match(/\(.*\)/)
    end
  end

  describe '#get_random_statements' do
    it 'returns an array' do
      expect(subject.send(:get_random_statements).class).to eq(Array)
    end
  end

  describe '#get_random_function_call' do
    it 'returns a function call' do
      expect(subject.send(:get_random_function_call).class).to eq(Array)
    end
  end
end