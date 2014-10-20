# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/encryptjs'

describe Rex::Exploitation::EncryptJS do

  let(:code) { "var test = 'metasploit';" }
  let(:key) { 'secret' }
  let(:signature) { 'metasploit' }
  let(:loader_signature) { 'location.search.substring(1);' }
  let(:loader_key_words) { ['exploit', 'encoded', 'pass', 'decoded'] }

  describe ".encrypt" do
    it "returns an String" do
      expect(Rex::Exploitation::EncryptJS.encrypt(code, key)).to be_an(String)
    end

    it "returns the JavaScript loader code" do
      expect(Rex::Exploitation::EncryptJS.encrypt(code, key)).to include(loader_signature)
    end

    it "encrypts the code" do
      expect(Rex::Exploitation::EncryptJS.encrypt(code, key)).to_not include(signature)
    end

    it "obfuscates the loader" do
      loader_key_words.each do |key_word|
        expect(Rex::Exploitation::EncryptJS.encrypt(code, key)).to_not include(key_word)
      end
    end

  end

end
