require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::StringAssignments do

  subject(:stringassignments) do
    described_class.new
  end

  describe '#stub' do
    it 'is a string' do
      expect(subject.stub.class).to be(String)
    end

    it 'assigns a string' do
      expect(subject.stub).to match(/const char\* .+ = ".+"/)
    end

    it 'has a stub() function' do
      expect(subject.stub).to match(/void stub()/)
    end
  end
end