# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Crypto::Des3CbcSha1 do
  subject(:encryptor) do
    described_class.new
  end

  it 'Key generation passes RFC 3961 test case 1' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["850bb51358548cd05e86768c313e3bfef7511937dcf72c3e"].pack("H*"))
  end

  it 'Key generation passes RFC 3961 test case 2' do
    password = 'potatoe'
    salt = 'WHITEHOUSE.GOVdanny'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["dfcd233dd0a43204ea6dc437fb15e061b02979c1f74f377a"].pack("H*"))
  end

  it 'Key generation passes RFC 3961 test case 3' do
    password = 'penny'
    salt = 'EXAMPLE.COMbuckaroo'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["6d2fcdf2d6fbbc3ddcadb5da5710a23489b0d3b69d5d9d4a"].pack("H*"))
  end

  it 'Key generation passes RFC 3961 test case 4' do
    password = "\u00df"
    salt = "ATHENA.MIT.EDUJuri\u0161i\u0107"

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["16d5a40e1ce3bacb61b9dce00470324c831973a7b952feb0"].pack("H*"))
  end

  it 'Key generation passes RFC 3961 test case 5' do
    password = "\u{1D11E}"
    salt = 'EXAMPLE.COMpianist'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19"].pack("H*"))
  end

  it 'Checksum is as expected' do
    # Test case based off impacket
    key = ['7A25DF8992296DCEDA0E135BC4046E2375B3C14C98FBC162'].pack('H*')
    keyusage = 2
    plaintext = 'six seven'
    expected_checksum = ['0EEFC9C3E049AABC1BA5C401677D9AB699082BB4'].pack('H*')
    checksum = encryptor.checksum(key, keyusage, plaintext)
    expect(checksum).to eq(expected_checksum)
  end

  it 'Crypto matches expected values' do
    # Test case based off impacket
    key = ['0DD52094E0F41CECCB5BE510A764B35176E3981332F1E598'].pack('H*')
    confounder = ['94690A17B2DA3C9B'].pack('H*')
    keyusage = 3
    plaintext = '13 bytes byte'
    ciphertext = ['839A17081ECBAFBCDC91B88C6955DD3C4514023CF177B77BF0D0177A16F705E849CB7781D76A316B193F8D30'].pack('H*')
    encrypted = encryptor.encrypt(plaintext, key, keyusage, confounder: confounder)
    decrypted = encryptor.decrypt(ciphertext, key, keyusage)

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

    expect(encrypted).to eq(ciphertext)
    expect(decrypted).to eq(plaintext)
  end

  it 'Decryption inverts encryption' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = ["85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19"].pack("H*")
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
    key = ["85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19"].pack("H*")
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    # Let's change the last bit of the MAC
    last_byte = encrypted[-1].ord
    last_byte ^= 1
    encrypted = encrypted[0,encrypted.length - 1] + last_byte.chr
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'HMAC integrity error')
  end

  it 'Invalid length throws error' do
    plaintext = "The quick brown fox jumps over the lazy dog"
    key = ["85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19"].pack("H*")
    msg_type = 4
    encrypted = encryptor.encrypt(plaintext, key, msg_type)
    # Let's remove one byte
    encrypted = encrypted[0,encrypted.length - 1]
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext is not a multiple of block length')
  end

  it 'Short length throws error' do
    key = ["85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19"].pack("H*")
    msg_type = 4
    encrypted = 'abc'
    expect { encryptor.decrypt(encrypted, key, msg_type) }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError, 'Ciphertext too short')
  end
end
