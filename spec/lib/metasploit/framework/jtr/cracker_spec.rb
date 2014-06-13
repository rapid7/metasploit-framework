require 'spec_helper'
require 'metasploit/framework/jtr/cracker'

describe Metasploit::Framework::JtR::Cracker do

  subject(:cracker) { described_class.new }

  describe '#binary_path' do
    context 'when the user supplied a john_path' do
      before(:each) do
        cracker.john_path = '/path/to/john'
      end

      it 'returns the manual path if it exists and is a regular file' do
        expect(::File).to receive(:file?).with(cracker.john_path).at_least(:once).and_return true
        expect(cracker.binary_path).to eq cracker.john_path
      end

      it 'rejects the manual path if it does not exist or is not a regular file' do
        expect(cracker.binary_path).to_not eq cracker.john_path
      end
    end

    context 'when the user did not supply a path' do
      it 'searches the Environment PATH' do
        expect(Rex::FileUtils).to receive(:find_full_path).and_return __FILE__
        expect(cracker.binary_path).to eq __FILE__
      end
    end
  end
end