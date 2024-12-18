require 'rspec'
require 'metasploit/framework/login_scanner/teamcity'

RSpec.describe Metasploit::Framework::LoginScanner::TeamCity do

  let(:subject) { described_class.new }

  # Sample public key taken from a running instance of TeamCity
  let(:teamcity_public_key) { 123745099044379560034534292817206769690406658656179033915532150868201038268331364602421054634661908195221281696003927960251442559477403753250293468778385622756011022439279250077496033565623853604577886813851441780820332383679913126402116420846511593354558582754642561605875011841424796003363034584971880190853 }

  describe '#two_byte_chars?' do
    [
      { input: 'abc', expected: false },
      { input: '', expected: false },
      { input: 'ççç', expected: false }, # has2byteChars('ç') -> false
      # I love metasploit
      { input: 'メタスプライトが大好きです', expected: true } # has2byteChars('メタスプライトが大好きです') -> true
    ].each do |scenario|
      it 'returns the correct value' do
        expect(subject.two_byte_chars?(scenario[:input])).to eq(scenario[:expected])
      end
    end

    [
      { input: nil },
      { input: true },
      { input: 123 },
      { input: [] }
    ].each do |scenario|
      it 'raises an error on incorrect type' do
        expect { subject.two_byte_chars?(scenario[:input]) }.to raise_error(ArgumentError)
      end
    end
  end

  describe '#max_data_size' do
    [
      { input: 'abc', expected: 116 },
      { input: '', expected: 116 },
      { input: 'ççç', expected: 116 },
      { input: 'メタスプライトが大好きです', expected: 58 } # I love metasploit
    ].each do |scenario|
      it 'returns the correct maximum message length' do
        expect(subject.max_data_size(scenario[:input])).to eq(scenario[:expected])
      end
    end

    [
      { input: nil },
      { input: true },
      { input: 123 },
      { input: [] }
    ].each do |scenario|
      it 'raises an error on incorrect type' do
        expect { subject.max_data_size(scenario[:input]) }.to raise_error(ArgumentError)
      end
    end
  end

  describe '#pkcs1pad2' do
    [
      { input: 'abc', expected: /0061626303$/ },
      { input: '', expected: /0000$/ },
      { input: 'ççç', expected: /00e7e7e703$/ }, # 3 chars, E7 codepoint
      { input: 'メタスプライトが大好きです', expected: /0030e130bf30b930d730e930a430c8304c5927597d304d306730590d$/ } # I love metasploit
    ].each do |scenario|
      it 'correctly pads text' do
        n = (teamcity_public_key.bit_length + 7) >> 3
        padded_as_big_int = subject.pkcs1pad2(scenario[:input], n)
        padded_hex = padded_as_big_int.to_s(16)
        expect(padded_hex).to match(scenario[:expected])
      end
    end

    [
      { input: nil, n: nil },
      { input: '', n: nil },
      { input: nil, n: 128 },
      { input: true, n: true },
    ].each do |scenario|
      it 'raises an error on incorrect type' do
        expect { subject.pkcs1pad2(scenario[:input], scenario[:n]) }.to raise_error(ArgumentError)
      end
    end

    [
      { input: 'a', n: 11 },
      { input: 'very_long_message_that_consists_of_many_characters', n: 40 }
    ].each do |scenario|
      it 'raises an error when message is too long' do
        expect { subject.pkcs1pad2(scenario[:input], scenario[:n]) }.to raise_error(ArgumentError)
      end
    end
  end
end
