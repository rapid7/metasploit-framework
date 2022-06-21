# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Crypto::Rc4Hmac do
  subject(:encryptor) do
    described_class.new
  end

  it 'Crypto matches expected values' do
    # Test case based off impacket
    key = ['68F263DB3FCE15D031C9EAB02D67107A'].pack('H*')
    confounder = ['37245E73A45FBF72'].pack('H*')
    keyusage = 4
    plaintext = '30 bytes bytes bytes bytes byt'
    ciphertext = ['95F9047C3AD75891C2E9B04B16566DC8B6EB9CE4231AFB2542EF87A7B5A0F260A99F0460508DE0CECC632D07C354124E46C5D2234EB8'].pack('H*')
    encrypted = encryptor.encrypt(plaintext, key, keyusage, confounder)
    decrypted = encryptor.decrypt(ciphertext, key, keyusage)

    expect(encrypted).to eq(ciphertext)
    expect(decrypted).to eq(plaintext)
  end


  it 'String to key genration is as expected' do
    # Test case based off impacket
    string = 'foo'
    key = ['AC8E657F83DF82BEEA5D43BDAF7800CC'].pack('H*')
    k = encryptor.string_to_key(string, nil)
    expect(k).to eq(key)
  end

  it 'Checksum is as expected' do
    # Test case based off impacket
    key = ['F7D3A155AF5E238A0B7A871A96BA2AB2'].pack('H*')
    keyusage = 6
    plaintext = 'seventeen eighteen nineteen twenty'
    expected_checksum = ['EB38CC97E2230F59DA4117DC5859D7EC'].pack('H*')
    checksum = encryptor.checksum(key, keyusage, plaintext)
    expect(checksum).to eq(expected_checksum)
  end
end
