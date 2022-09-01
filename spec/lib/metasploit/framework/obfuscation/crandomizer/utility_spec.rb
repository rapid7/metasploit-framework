require 'spec_helper'
require 'metasploit/framework/obfuscation/crandomizer/utility'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::Utility do

  describe '#self.rand_int' do
    it 'returns an integer' do
      int = Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int
      # Ruby at one point switched from Fixnum to Integer, so to support both,
      # it's easier to do a regex check.
      expect(int.to_s).to match(/^\d+$/)
    end

    it 'returns a random integer' do
      int_1 = Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int
      int_2 = Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int
      expect(int_2).not_to eq(int_1)
    end
  end

  describe '#self.rand_string' do
    it 'returns a string' do
      s = Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string
      expect(s.class).to eq(String)
    end

    it 'returns a random string' do
      s_1 = Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string
      s_2 = Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string
      expect(s_2).not_to eq(s_1)
    end
  end

  describe '#self.parse' do
    let(:c_code) {
      %Q|
      int main() {
        const char* s = "This is a test";
        return 0;
      }|
    }

    it 'returns a Metasploit::C::Parser object' do
      p = Metasploit::Framework::Obfuscation::CRandomizer::Utility.parse(c_code)
      expect(p.class).to eq(Metasm::C::Parser)
    end
  end

end