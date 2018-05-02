require 'spec_helper'
require 'securerandom'


RSpec.describe Rex::Crypto do

    let(:iv) {
      SecureRandom.random_bytes(16)
    }

    let(:key) {
      SecureRandom.random_bytes(32)
    }

    let(:value) {
      'Hello World'
    }

  describe '#encrypt_aes256' do
    it 'raises an exception due to a short IV' do
      iv = SecureRandom.random_bytes(1)
      # Because it could raise either a OpenSSL::Cipher::CipherError or an ArgumentError
      # dependong on the environment, we will just expect it to raise an exception
      expect { Rex::Crypto.encrypt_aes256(iv, key, value) }.to raise_exception
    end

    it 'raises an exception due to a short key' do
      key = SecureRandom.random_bytes(1)
      # Because it could raise either a OpenSSL::Cipher::CipherError or an ArgumentError
      # dependong on the environment, we will just expect it to raise an exception
      expect { Rex::Crypto.encrypt_aes256(iv, key, value) }.to raise_exception
    end

    it 'encrypts the string Hello World' do
      encrypted_str = Rex::Crypto.encrypt_aes256(iv, key, value)
      expect(encrypted_str).not_to eq(value)
    end
  end

  describe '#decrypt_aes256' do
    it 'raises an exception due to a short IV' do
      iv = SecureRandom.random_bytes(1)
      # Because it could raise either a OpenSSL::Cipher::CipherError or an ArgumentError
      # dependong on the environment, we will just expect it to raise an exception
      expect { Rex::Crypto.decrypt_aes256(iv, key, value) }.to raise_exception
    end

    it 'raises an exception due to a short key' do
      key = SecureRandom.random_bytes(1)
      # Because it could raise either a OpenSSL::Cipher::CipherError or an ArgumentError
      # dependong on the environment, we will just expect it to raise an exception
      expect { Rex::Crypto.decrypt_aes256(iv, key, value) }.to raise_exception
    end

    it 'decrypts the value to Hello World' do
      encrypted_str = Rex::Crypto.encrypt_aes256(iv, key, value)
      decrypted_str = Rex::Crypto.decrypt_aes256(iv, key, encrypted_str)
      expect(decrypted_str).to eq(value)
    end
  end

end