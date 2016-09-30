require 'spec_helper'
require 'metasploit/framework/jtr/cracker'

RSpec.describe Metasploit::Framework::JtR::Cracker do

  subject(:cracker) { described_class.new }
  let(:john_path) { '/path/to/john' }
  let(:other_john_path) { '/path/to/other/john' }
  let(:session_id) { 'Session1' }
  let(:config) { '/path/to/config.conf' }
  let(:pot) { '/path/to/john.pot' }
  let(:other_pot) { '/path/to/other/pot' }
  let(:wordlist) { '/path/to/wordlist' }
  let(:hash_path) { '/path/to/hashes' }
  let(:nt_format) { 'nt' }
  let(:incremental) { 'Digits5' }
  let(:rules)   { 'Rule34'}
  let(:max_runtime) { 5000 }

  describe '#binary_path' do


    context 'when the user supplied a john_path' do
      before(:example) do
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
    end
  end

  describe '#crack_command' do
    before(:example) do
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

    it 'uses default john.pot if the user did not supply one' do
      expect(cracker).to receive(:john_pot_file).and_return other_pot
      expect(cracker.crack_command).to include "--pot=#{other_pot}"
    end

    it 'uses the user supplied format directive' do
      cracker.format = nt_format
      expect(cracker.crack_command).to include "--format=#{nt_format}"
    end

    it 'uses the user supplied wordlist directive' do
      cracker.wordlist = wordlist
      expect(cracker.crack_command).to include "--wordlist=#{wordlist}"
    end

    it 'uses the user supplied incremental directive' do
      cracker.incremental = incremental
      expect(cracker.crack_command).to include "--incremental=#{incremental}"
    end

    it 'uses the user supplied rules directive' do
      cracker.rules = rules
      expect(cracker.crack_command).to include "--rules=#{rules}"
    end

    it 'uses the user supplied max-run-time' do
      cracker.max_runtime = max_runtime
      expect(cracker.crack_command).to include "--max-run-time=#{max_runtime.to_s}"
    end

    it 'puts the path to the has file at the end' do
      cracker.hash_path = hash_path
      expect(cracker.crack_command.last).to eq hash_path
    end

  end

  describe '#show_command' do
    before(:example) do
      expect(cracker).to receive(:binary_path).and_return john_path
    end

    it 'starts with the john binary path' do
      expect(cracker.show_command[0]).to eq john_path
    end

    it 'has the --show flag' do
      expect(cracker.show_command).to include '--show'
    end

    it 'uses the user supplied john.pot if there is one' do
      cracker.pot = pot
      expect(cracker.show_command).to include "--pot=#{pot}"
    end

    it 'uses default john.pot if the user did not supply one' do
      expect(cracker).to receive(:john_pot_file).and_return other_pot
      expect(cracker.show_command).to include "--pot=#{other_pot}"
    end

    it 'uses the user supplied format directive' do
      cracker.format = nt_format
      expect(cracker.show_command).to include "--format=#{nt_format}"
    end

    it 'puts the path to the has file at the end' do
      cracker.hash_path = hash_path
      expect(cracker.show_command.last).to eq hash_path
    end
  end

  describe 'validations' do
    context 'failures' do
      context 'file_path validators' do
        before(:example) do
          expect(File).to receive(:file?).and_return false
        end

        it 'produces the correct error message for config' do
          cracker.config = config
          expect(cracker).to_not be_valid
          expect(cracker.errors[:config]).to include "is not a valid path to a regular file"
        end

        it 'produces the correct error message for hash_path' do
          cracker.hash_path = hash_path
          expect(cracker).to_not be_valid
          expect(cracker.errors[:hash_path]).to include "is not a valid path to a regular file"
        end

        it 'produces the correct error message for pot' do
          cracker.pot = pot
          expect(cracker).to_not be_valid
          expect(cracker.errors[:pot]).to include "is not a valid path to a regular file"
        end

        it 'produces the correct error message for wordlist' do
          cracker.wordlist = wordlist
          expect(cracker).to_not be_valid
          expect(cracker.errors[:wordlist]).to include "is not a valid path to a regular file"
        end
      end

      context 'executable_path validators' do
        before(:example) do
          expect(File).to receive(:executable?).and_return false
        end

        it 'produces the correct error message for john_path' do
          cracker.john_path = john_path
          expect(cracker).to_not be_valid
          expect(cracker.errors[:john_path]).to include "is not a valid path to an executable file"
        end
      end
    end

    context 'successes' do
      context 'file_path validators' do
        before(:example) do
          expect(File).to receive(:file?).and_return true
        end

        it 'produces no error message for config' do
          cracker.config = config
          expect(cracker).to be_valid
          expect(cracker.errors[:config]).to_not include "is not a valid path to a regular file"
        end

        it 'produces no error message for hash_path' do
          cracker.hash_path = hash_path
          expect(cracker).to be_valid
          expect(cracker.errors[:hash_path]).to_not include "is not a valid path to a regular file"
        end

        it 'produces no error message for pot' do
          cracker.pot = pot
          expect(cracker).to be_valid
          expect(cracker.errors[:pot]).to_not include "is not a valid path to a regular file"
        end

        it 'produces no error message for wordlist' do
          cracker.wordlist = wordlist
          expect(cracker).to be_valid
          expect(cracker.errors[:wordlist]).to_not include "is not a valid path to a regular file"
        end
      end

      context 'executable_path validators' do
        before(:example) do
          expect(File).to receive(:executable?).and_return true
        end

        it 'produces no error message for john_path' do
          cracker.john_path = john_path
          expect(cracker).to be_valid
          expect(cracker.errors[:john_path]).to_not include "is not a valid path to an executable file"
        end
      end
    end
  end
end
