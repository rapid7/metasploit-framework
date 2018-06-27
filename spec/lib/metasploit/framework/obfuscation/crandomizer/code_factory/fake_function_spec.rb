require 'metasploit/framework/obfuscation/crandomizer/code_factory/fake_function'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunction do
  let(:function_name) do
    'test'
  end

  subject(:fake_function) do
    described_class.new(function_name)
  end

  describe '#initialize' do
    it 'sets attribute' do
      expect(subject.attribute.class).to eq(String)
    end

    it 'sets a return type' do
      expect(subject.return_type.class).to eq(String)
    end

    it 'sets an argument type' do
      expect(subject.args.class).to eq(String)
    end

    it 'sets function name' do
      expect(subject.function_name).to eq(function_name)
    end
  end

  describe '#generate_body' do
    it 'contains a return type' do
      return_type = subject.return_type
      expect(subject.generate_body).to match(/#{return_type}/)
    end

    it 'contains a function name' do
      expect(subject.generate_body).to match(/#{function_name}/)
    end
  end
end