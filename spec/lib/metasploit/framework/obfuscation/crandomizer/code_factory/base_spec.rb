require 'metasploit/framework/obfuscation/crandomizer/code_factory'
require 'metasploit/framework/obfuscation/crandomizer/utility'

RSpec.describe Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::Base do
  let(:stub_code) do
    %Q|
    void stub() {
      int x = 1;
    }|
  end

  subject(:base) do
    allow_any_instance_of(described_class).to receive(:stub).and_return(stub_code)
    described_class.new
  end

  describe '#stub' do
    it 'returns a string' do
      expect(base.stub.class).to be(String)
    end

    it 'returns the stub code' do
      expect(subject.stub).to eq(stub_code)
    end
  end

  describe '#good_dep?' do
    let(:source_code) do
      %Q|
      void printf(const char*);

      int main() {
        const char* s = "Hello World";
        printf(s);
        return 0;
      }|
    end

    let(:parser) do
      Metasploit::Framework::Obfuscation::CRandomizer::Utility.parse(source_code)
    end


    it 'returns true when the source supports printf' do
      allow(subject).to receive(:dep).and_return(['printf'])
      expect(subject.good_dep?(parser)).to be_truthy
    end

    it 'returns false when the source does not support OutputDebugString' do
      stub_code = %Q|
      void OutputDebugString(const char*);

      void stub() {
        OutputDebugString("test");
      }|

      allow(subject).to receive(:stub).and_return(stub_code)
      allow(subject).to receive(:dep).and_return(['OutputDebugString'])
      expect(subject.good_dep?(parser)).to be_falsy
    end
  end

  describe '#normalized_stub' do
    it 'normalizes the stub' do
      normalized_code = %Q|int x = 1;|
      expect(subject.normalized_stub.join).to eq(normalized_code)
    end
  end
end