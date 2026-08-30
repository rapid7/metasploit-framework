require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::Printf do

  subject(:printf) do
    described_class.new
  end

  describe '#stub' do
    it 'is a string' do
      expect(subject.stub.class).to be(String)
    end

    it 'has a printf' do
      expect(subject.stub).to match(/printf\(.+\)/)
    end

    it 'has a stub() function' do
      expect(subject.stub).to match(/void stub()/)
    end

    it 'depends on printf' do
      expect(subject.dep).to eq(['printf'])
    end
  end
end