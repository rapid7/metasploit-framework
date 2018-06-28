require 'metasploit/framework/obfuscation/crandomizer/code_factory'
require 'metasploit/framework/obfuscation/crandomizer/utility'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::Base do
  let(:source_code) do
    %Q|
    void printf(const char*);

    int main() {
      const char* s = "Hello World";
      printf(s);
      return 0;
    }|

    subject(:base) do
      b = described_class.new
      allow(b).to receive(:stub).and_return(source_code)
      b
    end

    describe '#stub' do
    end

    describe '#good_dep?' do
    end

    describe '#normalized_stub' do
    end
  end
end