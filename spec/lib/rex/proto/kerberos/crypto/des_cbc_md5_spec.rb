# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Crypto::DesCbcMd5 do
  subject(:encryptor) do
    described_class.new
  end

  it 'Key generation passes RFC 3961 test case 1' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq("\xcb\xc2\x2f\xae\x23\x52\x98\xe3")
  end

  it 'Key generation passes RFC 3961 test case 2' do
    password = 'potatoe'
    salt = 'WHITEHOUSE.GOVdanny'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq("\xdf\x3d\x32\xa7\x4f\xd9\x2a\x01")
  end

  it 'Key generation passes RFC 3961 test case 3' do
    password = "\u{1D11E}"
    salt = 'EXAMPLE.COMpianist'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq("\x4f\xfb\x26\xba\xb0\xcd\x94\x13")
  end

  it 'Key generation passes RFC 3961 test case 4' do
    password = "\u00df"
    salt = "ATHENA.MIT.EDUJuri\u0161i\u0107"

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq("\x62\xc8\x1a\x52\x32\xb5\xe6\x9d")
  end

  it 'Key generation passes RFC 3961 test case 5' do
    password = "11119999"
    salt = "AAAAAAAA"

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq("\x98\x40\x54\xd0\xf1\xa7\x3e\x31")
  end

  it 'Key generation passes RFC 3961 test case 6' do
    password = "NNNN6666"
    salt = "FFFFAAAA"

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq("\xc4\xbf\x6b\x25\xad\xf7\xa4\xf8")
  end

  it 'Decryption inverts encryption' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = "\xc4\xbf\x6b\x25\xad\xf7\xa4\xf8"
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    decrypted = encryptor.decrypt(encrypted, key, msg_type)
    
    # Null bytes at the end are expected, per RFC3961:
    #
    # The result of the decryption may be longer than the original
    # plaintext, as, for example, when the encryption mode adds padding
    # to reach a multiple of a block size.  If this is the case, any
    # extra octets must come after the decoded plaintext.  An
    # application protocol that needs to know the exact length of the
    # message must encode a length or recognizable "end of message"
    # marker within the plaintext

    while plaintext.length % described_class::BLOCK_SIZE != 0
      plaintext += "\x00"
    end

    expect(decrypted).to eq(plaintext)
  end

  it 'Broken MAC causes integrity failure' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = "\xc4\xbf\x6b\x25\xad\xf7\xa4\xf8"
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    # Let's change one bit of the ciphertext, which should exist somewhere inside the checksum
    mod_byte = encrypted[11].ord
    mod_byte ^= 1
    encrypted = encrypted[0,11] + mod_byte.chr + encrypted[12,encrypted.length]
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'HMAC integrity error')
  end

  it 'Invalid length throws error' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = "\xc4\xbf\x6b\x25\xad\xf7\xa4\xf8"
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    # Let's remove one byte
    encrypted = encrypted[0,encrypted.length - 1]
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext is not a multiple of block length')
  end

  it 'Short length throws error' do
    key = "\xc4\xbf\x6b\x25\xad\xf7\xa4\xf8"
    msg_type = 4
    encrypted = 'abc'
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext too short')
  end
end
