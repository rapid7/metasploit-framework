require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::If do

  subject(:if_statement) do
    described_class.new
  end

  describe '#if_stub' do
    it 'is a string' do
      expect(subject.send(:if_stub).class).to be(String)
    end

    it 'has an if statement' do
      expect(subject.send(:if_stub)).to match(/if (.+) {/)
    end

    it 'has a stub() function' do
      expect(subject.send(:if_stub)).to match(/void stub()/)
    end
  end

  describe '#if_if_else_stub' do
    it 'is a string' do
      expect(subject.send(:if_if_else_stub).class).to be(String)
    end

    it 'has an if statement' do
      expect(subject.send(:if_if_else_stub)).to match(/if (.+) {/)
    end

    it 'has an else if statement' do
      expect(subject.send(:if_if_else_stub)).to match(/else if (.+) /)
    end

    it 'has a stub() function' do
      expect(subject.send(:if_if_else_stub)).to match(/void stub()/)
    end
  end

  describe '#if_else_stub' do
    it 'is a string' do
      expect(subject.send(:if_else_stub).class).to be(String)
    end

    it 'has an if statement' do
      expect(subject.send(:if_else_stub)).to match(/if (.+) {/)
    end

    it 'has an else statement' do
      expect(subject.send(:if_else_stub)).to match(/else {/)
    end

    it 'has a stub() function' do
      expect(subject.send(:if_else_stub)).to match(/void stub()/)
    end
  end
end