# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        # This class provides a representation of a PAC_SERVER_CHECKSUM structure, which contains the
        # checksum using the key of the server.
        class ServerChecksum < Element

          # @!attribute version
          #   @return [Integer] The checksum type
          attr_accessor :checksum

          def checksum_length
            if checksum == Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES128 ||
              checksum == Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES256
              return 12
            elsif checksum == Rex::Proto::Kerberos::Crypto::Checksum::HMAC_MD5
              return 16
            end
            16 # default to old behaviour just in case
          end
          # Encodes the Rex::Proto::Kerberos::Pac::ServerChecksum
          #
          # @return [String]
          def encode
            encoded = ''
            encoded << [checksum].pack('V')
            encoded << "\x00" * checksum_length

            encoded
          end
        end

      end
    end
  end
end
