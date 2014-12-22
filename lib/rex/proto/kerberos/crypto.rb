# -*- coding: binary -*-
require 'rex/proto/kerberos/crypto/rc4_hmac'
require 'rex/proto/kerberos/crypto/rsa_md5'

module Rex
  module Proto
    module Kerberos
      module Crypto

        include Rex::Proto::Kerberos::Crypto::Rc4Hmac
        include Rex::Proto::Kerberos::Crypto::RsaMd5

        RSA_MD5 = 7
        RC4_HMAC = 23
      end
    end
  end
end