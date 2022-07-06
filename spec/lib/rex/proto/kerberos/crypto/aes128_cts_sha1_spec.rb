# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Crypto::Aes128CtsSha1 do
  subject(:encryptor) do
    described_class.new
  end

  it 'Key generation passes RFC 3962 test case 1' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    aes_key = encryptor.string_to_key(password, salt, params: [1].pack('N'))
    expect(aes_key).to eq("\x42\x26\x3c\x6e\x89\xf4\xfc\x28\xb8\xdf\x68\xee\x09\x79\x9f\x15")
  end

  it 'Key generation passes RFC 3962 test case 2' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    aes_key = encryptor.string_to_key(password, salt, params: [2].pack('N'))
    expect(aes_key).to eq("\xc6\x51\xbf\x29\xe2\x30\x0a\xc2\x7f\xa4\x69\xd6\x93\xbd\xda\x13")
  end

  it 'Key generation passes RFC 3962 test case 3' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    aes_key = encryptor.string_to_key(password, salt, params: [1200].pack('N'))
    expect(aes_key).to eq("\x4c\x01\xcd\x46\xd6\x32\xd0\x1e\x6d\xbe\x23\x0a\x01\xed\x64\x2a")
  end

  it 'Key generation passes RFC 3962 test case 4' do
    password = 'password'
    salt = ['1234567878563412'].pack('H*')

    aes_key = encryptor.string_to_key(password, salt, params: [5].pack('N'))
    expect(aes_key).to eq("\xe9\xb2\x3d\x52\x27\x37\x47\xdd\x5c\x35\xcb\x55\xbe\x61\x9d\x8e")
  end

  it 'Key generation passes RFC 3962 test case 5' do
    password = 'X' * 64
    salt = 'pass phrase equals block size'

    aes_key = encryptor.string_to_key(password, salt, params: [1200].pack('N'))
    expect(aes_key).to eq("\x59\xd1\xbb\x78\x9a\x82\x8b\x1a\xa5\x4e\xf9\xc2\x88\x3f\x69\xed")
  end

  it 'Key generation passes RFC 3962 test case 6' do
    password = 'X' * 65
    salt = 'pass phrase exceeds block size'

    aes_key = encryptor.string_to_key(password, salt, params: [1200].pack('N'))
    expect(aes_key).to eq("\xcb\x80\x05\xdc\x5f\x90\x17\x9a\x7f\x02\x10\x4c\x00\x18\x75\x1d")
  end

  it 'Key generation passes RFC 3962 test case 7' do
    password = "\u{1D11E}"
    salt = 'EXAMPLE.COMpianist'

    aes_key = encryptor.string_to_key(password, salt, params: [50].pack('N'))
    expect(aes_key).to eq("\xf1\x49\xc1\xf2\xe1\x54\xa7\x34\x52\xd4\x3e\x7f\xe6\x2a\x56\xe5")
  end

  it 'Crypto matches expected values' do
    # Test case based off impacket
    key = ['9062430C8CDA3388922E6D6A509F5B7A'].pack('H*')
    confounder = ['94B491F481485B9A0678CD3C4EA386AD'].pack('H*')
    keyusage = 2
    plaintext = '9 bytesss'
    ciphertext = ['68FB9679601F45C78857B2BF820FD6E53ECA8D42FD4B1D7024A09205ABB7CD2EC26C355D2F'].pack('H*')

    encrypted = encryptor.encrypt(plaintext, key, keyusage, confounder: confounder)
    decrypted = encryptor.decrypt(ciphertext, key, keyusage)

    expect(encrypted).to eq(ciphertext)
    expect(decrypted).to eq(plaintext)
  end

  it 'Checksum is as expected' do
    # Test case based off impacket
    key = ['9062430C8CDA3388922E6D6A509F5B7A'].pack('H*')
    keyusage = 3
    plaintext = 'eight nine ten eleven twelve thirteen'
    expected_checksum = ['01A4B088D45628F6946614E3'].pack('H*')
    checksum = encryptor.checksum(key, keyusage, plaintext)
    expect(checksum).to eq(expected_checksum)
  end

  it 'Decryption inverts encryption' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = "\xf1\x49\xc1\xf2\xe1\x54\xa7\x34\x52\xd4\x3e\x7f\xe6\x2a\x56\xe5"
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    decrypted = encryptor.decrypt(encrypted, key, msg_type)
    
    expect(decrypted).to eq(plaintext)
  end

  it 'Broken MAC causes integrity failure' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = "\xf1\x49\xc1\xf2\xe1\x54\xa7\x34\x52\xd4\x3e\x7f\xe6\x2a\x56\xe5"
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    # Let's change one bit of the ciphertext, which should exist somewhere inside the checksum
    mod_byte = encrypted[11].ord
    mod_byte ^= 1
    encrypted = encrypted[0,11] + mod_byte.chr + encrypted[12,encrypted.length]
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'HMAC integrity error')
  end

  it 'Short length throws error' do
    key = "\xf1\x49\xc1\xf2\xe1\x54\xa7\x34\x52\xd4\x3e\x7f\xe6\x2a\x56\xe5"
    msg_type = 4
    encrypted = 'abc'
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext too short')
  end
end
