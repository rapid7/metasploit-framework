require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::UninitVariables do

  subject(:uninitvariables) do
    described_class.new
  end

  describe '#char' do
    it 'returns a string' do
      expect(subject.send(:char).class).to be(String)
    end

    it 'is char' do
      expect(subject.send(:char)).to match(/char /)
    end
  end

  describe '#int' do
    it 'returns a string' do
      expect(subject.send(:int).class).to be(String)
    end

    it 'is an int' do
      expect(subject.send(:int)).to match(/int /)
    end
  end

  describe '#string' do
    it 'returns a string' do
      expect(subject.send(:string).class).to be(String)
    end

    it 'is a const char*' do
      expect(subject.send(:string)).to match(/const char\* /)
    end
  end
end