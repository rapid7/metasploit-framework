# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        class PrivSvrChecksum < Element

          # @!attribute version
          #   @return [Fixnum] The checksum type
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