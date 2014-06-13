require 'spec_helper'
require 'metasploit/framework/jtr/cracker'

describe Metasploit::Framework::JtR::Cracker do

  subject(:cracker) { described_class.new }
  let(:john_path) { '/path/to/john' }
  let(:other_john_path) { '/path/to/other/john' }
  let(:session_id) { 'Session1' }
  let(:config) { '/path/to/config.conf' }
  let(:pot) { '/path/to/john.pot' }
  let(:other_pot) { '/path/to/other/pot' }
  let(:wordlist) { '/path/to/wordlist' }
  let(:hash_path) { '/path/to/hashes' }

  describe '#binary_path' do


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

  describe '#crack_command' do
    before(:each) do
      expect(cracker).to receive(:binary_path).and_return john_path
      expect(cracker).to receive(:john_session_id).and_return session_id
    end

    it 'starts with the john binary path' do
      expect(cracker.crack_command[0]).to eq john_path
    end

    it 'sets a session id' do
      expect(cracker.crack_command).to include "--session=#{session_id}"
    end

    it 'sets the nolog flag' do
      expect(cracker.crack_command).to include '--nolog'
    end

    it 'adds a config directive if the user supplied one' do
      cracker.config = config
      expect(cracker.crack_command).to include "--config=#{config}"
    end

    it 'does not use a config directive if not supplied one' do
      expect(cracker.crack_command).to_not include "--config=#{config}"
    end

    it 'uses the user supplied john.pot if there is one' do
      cracker.pot = pot
      expect(cracker.crack_command).to include "--pot=#{pot}"
    end

    it 'uses default john.pot if the user didnot supply one' do
      expect(cracker).to receive(:john_pot_file).and_return other_pot
      expect(cracker.crack_command).to include "--pot=#{other_pot}"
    end

  end
end