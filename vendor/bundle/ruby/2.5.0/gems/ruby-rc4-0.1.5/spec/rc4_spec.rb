#!/usr/bin/env ruby
# coding: ascii

require 'rc4'
require 'rspec'

describe RC4 do
  it "should not crypt with a blank key" do
    expect { 
      RC4.new("")
    }.to raise_error(SyntaxError, "RC4: Key supplied is blank")
 
  end

  it "should encrypt and decrypt password 'super-cool-test' with key 'nuff rspec'" do
    key = "nuff rspec"
    enc = RC4.new(key)
    encrypted = enc.encrypt("super-cool-test")

    dec = RC4.new(key)
    decrypted = dec.decrypt(encrypted)
    decrypted.should match(/super-cool-test/)
  end

  it "should encrypt and decrypt password 'if-I-was-a-bit' with key 'bitsnbytes'" do
    enc = RC4.new('bitsnbytes') 
    dec = RC4.new('bitsnbytes') 

    encrypted = enc.encrypt("if-I-was-a-bit")
    decrypted = dec.decrypt(encrypted)
    decrypted.should match(/if-I-was-a-bit/)
  end


  # test samples taken from:
  # http://en.wikipedia.org/wiki/RC4#Test_vectors

  it "should decrypt ciphertext 'BBF316E8D940AF0AD3' with key 'Key' to 'Plaintext'" do
    dec = RC4.new('Key')

    decrypted = dec.decrypt(['BBF316E8D940AF0AD3'].pack("H*"))
    decrypted.should match(/Plaintext/)
  end

  it "should decrypt ciphertext '1021BF0420' with key 'Wiki' to 'pedia' " do
    dec = RC4.new('Wiki')

    decrypted = dec.decrypt(['1021BF0420'].pack("H*"))
    decrypted.should match(/pedia/)
  end

  it "should decrypt ciphertext '45A01F645FC35B383552544B9BF5' with key 'Secret' to 'Attack at dawn'" do
    dec = RC4.new('Secret')

    decrypted = dec.decrypt(['45A01F645FC35B383552544B9BF5'].pack("H*"))
    decrypted.should match(/Attack at dawn/)
  end
end


