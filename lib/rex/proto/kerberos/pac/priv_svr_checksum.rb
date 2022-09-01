# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        # This class provides a representation of a PAC_PRIVSVR_CHECKSUM structure, which contains the
        # checksum using the key of the KDC.
        class PrivSvrChecksum < Element

          # @!attribute version
          #   @return [Integer] The checksum type
          attr_accessor :checksum

          # Encodes the Rex::Proto::Kerberos::Pac::PacPrivSvrChecksum
          #
          # @return [String]
          def encode
            encoded = ''
            encoded << [checksum].pack('V')
            encoded << "\x00" * 16

            encoded
          end
        end
      end
    end
  end
end