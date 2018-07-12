require 'metasploit/framework/obfuscation/crandomizer/code_factory'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::GetTickCount do

  subject(:get_tick_count) do
    described_class.new
  end

  describe 'dep' do
    it 'depends on GetTickCount' do
      expect(subject.dep).to eq(['GetTickCount'])
    end
  end

  describe '#single_gettickcount' do
    it 'is a string' do
      expect(subject.send(:single_gettickcount).class).to be(String)
    end

    it 'has a GetTickCount() declaration' do
      expect(subject.send(:single_gettickcount)).to match(/int GetTickCount()/)
    end

    it 'has a stub() function' do
      expect(subject.send(:single_gettickcount)).to match(/void stub()/)
    end
  end

  describe '#diff_gettickcount' do
    it 'is a string' do
      expect(subject.send(:diff_gettickcount).class).to be(String)
    end

    it 'has a GetTickCount() declaration' do
      expect(subject.send(:diff_gettickcount)).to match(/int GetTickCount()/)
    end

    it 'has a stub() function' do
      expect(subject.send(:diff_gettickcount)).to match(/void stub()/)
    end
  end

end