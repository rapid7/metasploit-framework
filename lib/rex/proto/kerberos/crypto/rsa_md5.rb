# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto
        class RsaMd5
          # The MD5 checksum of the data
          #
          # @param key [String] ignored for this checksum type
          # @param msg_type [Integer] ignored for this checksum type
          # @param data [String] the data to checksum
          # @return [String] the generated checksum
          def checksum(key, msg_type, data)
            Rex::Text.md5_raw(data)
          end
        end
      end
    end
  end
end
