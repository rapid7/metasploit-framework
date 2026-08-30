require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::Switch do

  subject(:switch) do
    described_class.new
  end

  describe '#switch_1' do
    it 'is a string' do
      expect(subject.send(:switch_1).class).to be(String)
    end

    it 'has a switch' do
      expect(subject.send(:switch_1)).to match(/switch(.+)/)
    end

    it 'has a default' do
      expect(subject.send(:switch_1)).to match(/default:/)
    end
  end

  describe '#switch_2' do
    it 'is a string' do
      expect(subject.send(:switch_2).class).to be(String)
    end

    it 'has a switch' do
      expect(subject.send(:switch_2)).to match(/switch(.+)/)
    end
  end
end