# -*- coding: binary -*-

##
#
# RFB protocol support
#
# by Joshua J. Drake <jduck>
#
# Based on:
# vnc_auth_none contributed by Matteo Cantoni <goony[at]nothink.org>
# vnc_auth_login contributed by carstein <carstein.sec[at]gmail.com>
#
##

# Required for VNC authentication
require 'openssl'

module Rex
module Proto
module RFB

##
# A bit of information about the DES algorithm was found here:
# http://www.vidarholen.net/contents/junk/vnc.html
#
# In addition, VNC uses two individual 8 byte block encryptions rather than
# using any block mode (like cbc, ecb, etc).
##

class Cipher

  def self.mangle_password(password)
    key = ''
    key = password.dup if password
    key.slice!(8,key.length) if key.length > 8
    key << "\x00" * (8 - key.length) if key.length < 8

    # We have to mangle the key so the LSB are kept vs the MSB
    [key.unpack('B*').first.scan(/.{8}/).map! { |e| e.reverse }.join].pack('B*')
  end

  def self.encrypt(plain, password)
    key = self.mangle_password(password)

    # pad the plain to 16 chars
    plain << ("\x00" * (16 - plain.length)) if plain.length < 16

    # VNC auth does two 8-byte blocks individually instead supporting some block mode
    cipher = ''
    2.times { |x|
      c = OpenSSL::Cipher.new('des')
      c.encrypt
      c.key = key
      cipher << c.update(plain[x*8, 8])
    }

    cipher
  end

  #
  # NOTE: The default password is that of winvnc/etc which is used for
  # encrypting the password(s) on disk/in registry.
  #
  def self.decrypt(cipher, password = "\x17\x52\x6b\x06\x23\x4e\x58\x07")
    key = self.mangle_password(password)

    # pad the cipher text to 9 bytes
    cipher << ("\x00" * (9 - cipher.length)) if cipher.length < 9

    # NOTE: This only does one 8 byte block
    plain = ''
    c = OpenSSL::Cipher.new('des')
    c.decrypt
    c.key = key
    c.update(cipher)
  end


  def self.encrypt_ard(username, password, generator, key_length, prime_modulus, peer_public_key)
    generator = OpenSSL::BN.new(generator, 2)
    prime_modulus = OpenSSL::BN.new(prime_modulus, 2)
    peer_public_key = OpenSSL::BN.new(peer_public_key, 2)

    user_struct = username + ("\0" * (64 - username.length)) + password + ("\0" * (64 - password.length))

    dh_peer = OpenSSL::PKey::DH.new(key_length * 8, generator)
    dh_peer.set_key(peer_public_key, nil)

    dh = OpenSSL::PKey::DH.new(dh_peer)
    dh.set_pqg(prime_modulus, nil, generator)
    dh.generate_key!

    shared_key = dh.compute_key(dh_peer.pub_key)

    md5 = OpenSSL::Digest::MD5.new
    key_digest = md5.digest(shared_key)

    cipher = OpenSSL::Cipher.new("aes-128-ecb")
    cipher.encrypt
    cipher.key = key_digest
    cipher.padding = 0
    ciphertext = cipher.update(user_struct) + cipher.final

    response = ciphertext + dh.pub_key.to_s(2)
    return response
  end

end

end
end
end
