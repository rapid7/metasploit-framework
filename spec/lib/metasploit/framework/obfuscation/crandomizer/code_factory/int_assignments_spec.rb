require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::IntAssignments do

  subject(:int_assignments) do
    described_class.new
  end

  describe '#stub' do
    it 'is a string' do
      expect(subject.send(:stub).class).to be(String)
    end

    it 'has an int assignment' do
      expect(subject.send(:stub)).to match(/int .+ = \d+/)
    end

    it 'has a stub() function' do
      expect(subject.send(:stub)).to match(/void stub()/)
    end
  end
end