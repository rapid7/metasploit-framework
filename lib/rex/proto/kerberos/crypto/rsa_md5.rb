# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto
        module RsaMd5
          def checksum_rsa_md5(data)
            md5 = OpenSSL::Digest::MD5.new
            md5 << data

            md5.digest
          end
        end
      end
    end
  end
end