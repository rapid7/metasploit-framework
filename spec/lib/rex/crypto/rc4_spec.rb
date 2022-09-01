require 'spec_helper'
require 'securerandom'


RSpec.describe Rex::Crypto do

  describe '#rc4' do

    let(:key) {
      SecureRandom.random_bytes(32)
    }

    let(:value) {
      'Hello World'
    }

    it 'encrypts a string' do
      expect(Rex::Crypto.rc4(key, value)).not_to eq(value)
    end

    it 'decrypts a string' do
      encrypted_str = Rex::Crypto.rc4(key, value)
      decrypted_str = Rex::Crypto.rc4(key, encrypted_str)
      expect(decrypted_str).to eq(value)
    end

  end
end