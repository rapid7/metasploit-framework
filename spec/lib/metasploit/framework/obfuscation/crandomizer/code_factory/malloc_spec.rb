require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::Malloc do

  subject(:int_assignments) do
    described_class.new
  end

  describe '#stub' do
    it 'is a string' do
      expect(subject.send(:stub).class).to be(String)
    end

    it 'has a malloc' do
      expect(subject.send(:stub)).to match(/malloc\(\d+\)/)
    end

    it 'has a stub() function' do
      expect(subject.send(:stub)).to match(/void stub()/)
    end

    it 'depends on malloc' do
      expect(subject.dep).to eq(['malloc'])
    end
  end
end