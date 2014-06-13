require 'spec_helper'
require 'metasploit/framework/jtr/cracker'

describe Metasploit::Framework::JtR::Cracker do

  subject(:cracker) { described_class.new }

  describe '#binary_path' do
    let(:john_path) { '/path/to/john' }
    let(:other_john_path) { '/path/to/other/john' }

    context 'when the user supplied a john_path' do
      before(:each) do
        cracker.john_path = john_path
      end

      it 'returns the manual path if it exists and is a regular file' do
        expect(::File).to receive(:file?).with(john_path).once.and_return true
        expect(cracker.binary_path).to eq john_path
      end

      it 'rejects the manual path if it does not exist or is not a regular file' do
        expect(::File).to receive(:file?).with(john_path).once.and_return false
        expect(Rex::FileUtils).to receive(:find_full_path).with('john').and_return other_john_path
        expect(::File).to receive(:file?).with(other_john_path).once.and_return true
        expect(cracker.binary_path).to_not eq john_path
      end
    end

    context 'when the user did not supply a path' do
      it 'returns the john binary from the PATH if it exists' do
        expect(Rex::FileUtils).to receive(:find_full_path).and_return john_path
        expect(::File).to receive(:file?).with(john_path).once.and_return true
        expect(cracker.binary_path).to eq john_path
      end

      it 'returns the shipped john binary if it does not exist in the PATH' do
        expect(Rex::FileUtils).to receive(:find_full_path).twice.and_return nil
        expect(::File).to receive(:file?).with(nil).once.and_return false
        expect(cracker).to receive(:select_shipped_binary).and_return other_john_path
        expect(cracker.binary_path).to eq other_john_path
      end
    end
  end
end