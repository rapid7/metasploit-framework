# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto
        module RsaMd5
          def checksum_rsa_md5(data)
            Rex::Text.md5_raw(data)
          end
        end
      end
    end
  end
end