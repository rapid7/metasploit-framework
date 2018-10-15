require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunctionCollection do
  let(:max_function_count) do
    3
  end

  subject(:fake_function_collection) do
    described_class.new(max_function_count)
  end

  describe '#initialize' do
    it 'sets functions' do
      expect(subject.functions.class).to eq(Array)
      expect(subject.functions.length).to eq(max_function_count)
    end

    it 'sets the max function count' do
      expect(subject.max_functions).to eq(max_function_count)
    end
  end

  describe '#sample' do
    it 'returns a Metasm::C::Declaration object' do
      expect(subject.sample.class).to eq(Metasm::C::Declaration)
    end
  end

  describe '#to_s' do
    it 'converts function objects to a string' do
      str = subject.to_s
      expect(str).to match(/function\d+\s*(__attribute__)*\s*\(.*\)\s*{.*}/)
    end
  end

  describe '#has_function_name?' do
    it 'returns true if a function name is found' do
      good_function_name = 'function1'
      expect(subject.has_function_name?(good_function_name)).to be_truthy
    end

    it 'returns false if a function is not found' do
      bad_function_name = 'badfunctionname'
      expect(subject.has_function_name?(bad_function_name)).to be_falsy
    end
  end

end