require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::OutputDebugString do

  subject(:outputdebugstring) do
    described_class.new
  end

  describe '#outputdebugstring_1' do
    it 'is a string' do
      expect(subject.send(:outputdebugstring_1).class).to be(String)
    end

    it 'has an OutputDebugString' do
      expect(subject.send(:outputdebugstring_1)).to match(/OutputDebugString\(.+\)/)
    end

    it 'has a stub() function' do
      expect(subject.send(:outputdebugstring_1)).to match(/void stub()/)
    end

    it 'depends on OutputDebugString' do
      expect(subject.dep).to eq(['OutputDebugString'])
    end
  end

  describe '#outputdebugstring_2' do
    it 'is a string' do
      expect(subject.send(:outputdebugstring_2).class).to be(String)
    end

    it 'has an OutputDebugString' do
      expect(subject.send(:outputdebugstring_2)).to match(/OutputDebugString\(.+\)/)
    end

    it 'has a stub() function' do
      expect(subject.send(:outputdebugstring_2)).to match(/void stub()/)
    end

    it 'depends on OutputDebugString' do
      expect(subject.dep).to eq(['OutputDebugString'])
    end
  end
end