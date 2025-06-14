# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Crypto::Aes256CtsSha1 do
  subject(:encryptor) do
    described_class.new
  end

  it 'Key generation passes RFC 3962 test case 1' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    aes_key = encryptor.string_to_key(password, salt, params: [1].pack('N'))
    expect(aes_key).to eq("\xfe\x69\x7b\x52\xbc\x0d\x3c\xe1\x44\x32\xba\x03\x6a\x92\xe6\x5b\xbb\x52\x28\x09\x90\xa2\xfa\x27\x88\x39\x98\xd7\x2a\xf3\x01\x61")
  end

  it 'Key generation passes RFC 3962 test case 2' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    aes_key = encryptor.string_to_key(password, salt, params: [2].pack('N'))
    expect(aes_key).to eq("\xa2\xe1\x6d\x16\xb3\x60\x69\xc1\x35\xd5\xe9\xd2\xe2\x5f\x89\x61\x02\x68\x56\x18\xb9\x59\x14\xb4\x67\xc6\x76\x22\x22\x58\x24\xff")
  end

  it 'Key generation passes RFC 3962 test case 3' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    aes_key = encryptor.string_to_key(password, salt, params: [1200].pack('N'))
    expect(aes_key).to eq("\x55\xa6\xac\x74\x0a\xd1\x7b\x48\x46\x94\x10\x51\xe1\xe8\xb0\xa7\x54\x8d\x93\xb0\xab\x30\xa8\xbc\x3f\xf1\x62\x80\x38\x2b\x8c\x2a")
  end

  it 'Key generation passes RFC 3962 test case 4' do
    password = 'password'
    salt = ['1234567878563412'].pack('H*')

    aes_key = encryptor.string_to_key(password, salt, params: [5].pack('N'))
    expect(aes_key).to eq("\x97\xa4\xe7\x86\xbe\x20\xd8\x1a\x38\x2d\x5e\xbc\x96\xd5\x90\x9c\xab\xcd\xad\xc8\x7c\xa4\x8f\x57\x45\x04\x15\x9f\x16\xc3\x6e\x31")
  end

  it 'Key generation passes RFC 3962 test case 5' do
    password = 'X' * 64
    salt = 'pass phrase equals block size'

    aes_key = encryptor.string_to_key(password, salt, params: [1200].pack('N'))
    expect(aes_key).to eq("\x89\xad\xee\x36\x08\xdb\x8b\xc7\x1f\x1b\xfb\xfe\x45\x94\x86\xb0\x56\x18\xb7\x0c\xba\xe2\x20\x92\x53\x4e\x56\xc5\x53\xba\x4b\x34")
  end

  it 'Key generation passes RFC 3962 test case 6' do
    password = 'X' * 65
    salt = 'pass phrase exceeds block size'

    aes_key = encryptor.string_to_key(password, salt, params: [1200].pack('N'))
    expect(aes_key).to eq("\xd7\x8c\x5c\x9c\xb8\x72\xa8\xc9\xda\xd4\x69\x7f\x0b\xb5\xb2\xd2\x14\x96\xc8\x2b\xeb\x2c\xae\xda\x21\x12\xfc\xee\xa0\x57\x40\x1b")
  end

  it 'Key generation passes RFC 3962 test case 7' do
    password = "\u{1D11E}"
    salt = 'EXAMPLE.COMpianist'

    aes_key = encryptor.string_to_key(password, salt, params: [50].pack('N'))
    expect(aes_key).to eq("\x4b\x6d\x98\x39\xf8\x44\x06\xdf\x1f\x09\xcc\x16\x6d\xb4\xb8\x3c\x57\x18\x48\xb7\x84\xa3\xd6\xbd\xc3\x46\x58\x9a\x3e\x39\x3f\x9e")
  end

  it 'Crypto matches expected values' do
    # Test case based off impackec
    key = ['F1C795E9248A09338D82C3F8D5B567040B0110736845041347235B1404231398'].pack('H*')
    confounder = ['E45CA518B42E266AD98E165E706FFB60'].pack('H*')
    keyusage = 4
    plaintext = '30 bytes bytes bytes bytes byt'
    ciphertext = ['D1137A4D634CFECE924DBC3BF6790648BD5CFF7DE0E7B99460211D0DAEF3D79A295C688858F3B34B9CBD6EEBAE81DAF6B734D4D498B6714F1C1D'].pack('H*')
    encrypted = encryptor.encrypt(plaintext, key, keyusage, confounder: confounder)
    decrypted = encryptor.decrypt(ciphertext, key, keyusage)

    expect(encrypted).to eq(ciphertext)
    expect(decrypted).to eq(plaintext)
  end

  it 'Checksum is as expected' do
    # Test case based off impacket
    key = ['B1AE4CD8462AFF1677053CC9279AAC30B796FB81CE21474DD3DDBCFEA4EC76D7'].pack('H*')
    keyusage = 4
    plaintext = 'fourteen'
    expected_checksum = ['E08739E3279E2903EC8E3836'].pack('H*')
    checksum = encryptor.checksum(key, keyusage, plaintext)
    expect(checksum).to eq(expected_checksum)
  end

  it 'Decryption inverts encryption' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = "\xfe\x69\x7b\x52\xbc\x0d\x3c\xe1\x44\x32\xba\x03\x6a\x92\xe6\x5b\xbb\x52\x28\x09\x90\xa2\xfa\x27\x88\x39\x98\xd7\x2a\xf3\x01\x61"
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    decrypted = encryptor.decrypt(encrypted, key, msg_type)
    
    expect(decrypted).to eq(plaintext)
  end

  it 'Broken MAC causes integrity failure' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = "\xfe\x69\x7b\x52\xbc\x0d\x3c\xe1\x44\x32\xba\x03\x6a\x92\xe6\x5b\xbb\x52\x28\x09\x90\xa2\xfa\x27\x88\x39\x98\xd7\x2a\xf3\x01\x61"
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    # Let's change one bit of the ciphertext, which should exist somewhere inside the checksum
    mod_byte = encrypted[11].ord
    mod_byte ^= 1
    encrypted = encrypted[0,11] + mod_byte.chr + encrypted[12,encrypted.length]
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'HMAC integrity error')
  end

  it 'Short length throws error' do
    key = "\xfe\x69\x7b\x52\xbc\x0d\x3c\xe1\x44\x32\xba\x03\x6a\x92\xe6\x5b\xbb\x52\x28\x09\x90\xa2\xfa\x27\x88\x39\x98\xd7\x2a\xf3\x01\x61"
    msg_type = 4
    encrypted = 'abc'
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext too short')
  end
end
