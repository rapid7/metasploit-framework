require 'spec_helper'
require 'metasploit/framework/password_crackers/wordlist'

RSpec.describe Metasploit::Framework::PasswordCracker::Wordlist do

  subject(:wordlist) { described_class.new }

  let(:custom_wordlist) { File.expand_path('string_list.txt',FILE_FIXTURES_PATH) }
  let(:expansion_word) { 'Foo bar_baz-bat.bam\\foo//bar' }
  let(:common_root_path) { File.expand_path('fake_common_roots.txt',FILE_FIXTURES_PATH) }
  let(:default_wordlist_path) { File.expand_path('fake_default_wordlist.txt',FILE_FIXTURES_PATH) }
  let(:password) { FactoryBot.create(:metasploit_credential_password) }
  let(:public) { FactoryBot.create(:metasploit_credential_public) }
  let(:realm) { FactoryBot.create(:metasploit_credential_realm) }
  let(:mutate_me) { 'password' }
  let(:mutants) {  [
      "pa55word",
      "password",
      "pa$$word",
      "passw0rd",
      "pa55w0rd",
      "pa$$w0rd",
      "p@ssword",
      "p@55word",
      "p@$$word",
      "p@ssw0rd",
      "p@55w0rd",
      "p@$$w0rd"
  ] }

  it { is_expected.to respond_to :appenders }
  it { is_expected.to respond_to :custom_wordlist }
  it { is_expected.to respond_to :mutate }
  it { is_expected.to respond_to :prependers }
  it { is_expected.to respond_to :use_common_root }
  it { is_expected.to respond_to :use_creds }
  it { is_expected.to respond_to :use_db_info }
  it { is_expected.to respond_to :use_default_wordlist }
  it { is_expected.to respond_to :use_hostnames }

  describe 'validations' do

    it 'raises an error if the custom_wordlist does not exist on the filesystem' do
      expect(File).to receive(:file?).and_return false
      wordlist.custom_wordlist = custom_wordlist
      expect(wordlist).to_not be_valid
      expect(wordlist.errors[:custom_wordlist]).to include "is not a valid path to a regular file"
    end

    it 'raises an error if mutate is not set to true or false' do
      expect(wordlist).to_not be_valid
      expect(wordlist.errors[:mutate]).to include "must be true or false"
    end

    it 'raises an error if use_common_root is not set to true or false' do
      expect(wordlist).to_not be_valid
      expect(wordlist.errors[:use_common_root]).to include "must be true or false"
    end

    it 'raises an error if use_creds is not set to true or false' do
      expect(wordlist).to_not be_valid
      expect(wordlist.errors[:use_creds]).to include "must be true or false"
    end

    it 'raises an error if use_db_info is not set to true or false' do
      expect(wordlist).to_not be_valid
      expect(wordlist.errors[:use_db_info]).to include "must be true or false"
    end

    it 'raises an error if use_default_wordlist is not set to true or false' do
      expect(wordlist).to_not be_valid
      expect(wordlist.errors[:use_default_wordlist]).to include "must be true or false"
    end

    it 'raises an error if use_hostnames is not set to true or false' do
      expect(wordlist).to_not be_valid
      expect(wordlist.errors[:use_hostnames]).to include "must be true or false"
    end
  end

  describe '#valid!' do
    it 'raises an InvalidWordlist exception if not valid?' do
      expect{ wordlist.valid! }.to raise_error Metasploit::Framework::PasswordCracker::InvalidWordlist
    end
  end

  describe '#expanded_words' do
    it 'yields all the possible component words in the string' do
      expect { |b| wordlist.expanded_words(expansion_word,&b) }.to yield_successive_args('Foo','bar','baz','bat','bam','foo','bar')
    end
  end

  describe '#each_custom_word' do
    it 'yields each word in that wordlist' do
      wordlist.custom_wordlist = custom_wordlist
      expect{ |b| wordlist.each_custom_word(&b) }.to yield_successive_args('foo', 'bar','baz')
    end
  end

  describe '#each_root_word' do
    it 'yields each word in the common_roots.txt list' do
      expect(wordlist).to receive(:common_root_words_path).and_return common_root_path
      expect { |b| wordlist.each_root_word(&b) }.to yield_successive_args('password', 'root', 'toor')
    end
  end

  describe '#each_default_word' do
    it 'yields each word in the passwords.lst list' do
      expect(wordlist).to receive(:default_wordlist_path).and_return default_wordlist_path
      expect { |b| wordlist.each_default_word(&b) }.to yield_successive_args('changeme', 'summer123', 'admin')
    end
  end

  define '#each_cred_word' do
    it 'yields each username,password,and realm in the database' do
      expect{ |b| wordlist.each_cred_word(&b) }.to yield_successive_args(password.data, public,username, realm,value)
    end
  end

  describe '#mutate_word' do
    it 'returns an array with all possible mutations of the word' do
      expect(wordlist.mutate_word(mutate_me)).to eq mutants
    end
  end

  describe '#each_mutated_word' do
    it 'yields each unique mutated word if mutate set to true' do
      wordlist.mutate = true
      expect { |b| wordlist.each_mutated_word(mutate_me,&b)}.to yield_successive_args(*mutants)
    end

    it 'yields the original word if mutate set to true' do
      wordlist.mutate = false
      expect { |b| wordlist.each_mutated_word(mutate_me,&b)}.to yield_with_args(mutate_me)
    end
  end

end
