# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::Authenticator do

  subject(:authenticator) do
    described_class.new
  end

  let(:rsa_md5) { Rex::Proto::Kerberos::Crypto::RSA_MD5 }

  let(:sample) do
    "\x62\x7c\x30\x7a\xa0\x03\x02\x01\x05\xa1\x0c\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f" +
    "\x43\x41\x4c\xa2\x11\x30\x0f\xa0\x03\x02\x01\x01\xa1\x08\x30\x06\x1b\x04\x6a\x75" +
    "\x61\x6e\xa3\x1b\x30\x19\xa0\x03\x02\x01\x07\xa1\x12\x04\x10\x9e\xf0\x84\xd6\x81" +
    "\xe5\x16\x02\x32\xb1\xc3\x4e\xad\x83\x1d\x43\xa4\x05\x02\x03\x0a\xf8\x98\xa5\x11" +
    "\x18\x0f\x32\x30\x31\x34\x31\x32\x31\x36\x32\x32\x35\x30\x34\x36\x5a\xa6\x1b\x30" +
    "\x19\xa0\x03\x02\x01\x17\xa1\x12\x04\x10\x7d\x63\xdd\x79\x73\x67\xce\x86\xbb\x5f" +
    "\x2b\x8a\xba\x58\xfd\x6e"
   end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::Authenticator correctly" do
      checksum = Rex::Proto::Kerberos::Model::Checksum.new(
        type: rsa_md5,
        checksum: "\x9e\xf0\x84\xd6\x81\xe5\x16\x02\x32\xb1\xc3\x4e\xad\x83\x1d\x43"
      )

      cname = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: 1,
        name_string: ['juan']
      )

      enc_key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
        type: Rex::Proto::Kerberos::Crypto::RC4_HMAC,
        value: "\x7d\x63\xdd\x79\x73\x67\xce\x86\xbb\x5f\x2b\x8a\xba\x58\xfd\x6e"
      )

      authenticator.vno = 5
      authenticator.crealm = 'DEMO.LOCAL'
      authenticator.cname = cname
      authenticator.checksum = checksum
      authenticator.cusec = 719000
      authenticator.ctime = Time.at(1418770246)
      authenticator.subkey = enc_key

      expect(authenticator.encode).to eq(sample)
    end
  end
end
