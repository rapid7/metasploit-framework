# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        # This class provides a representation of a PAC-CLIENT-INFO structure, containing the client's name
        # and authentication time. It's used to verify which the ticket's client is the PAC's owner.
        class ClientInfo < Element

          # @!attribute client_id
          #   @return [Time] The auth_time field of the Kerberos KDC-AS response.
          attr_accessor :client_id
          # @!attribute name
          #   @return [String] The client name from the ticket
          attr_accessor :name

          # Encodes the Rex::Proto::Kerberos::Pac::ClientInfo
          #
          # @return [String]
          def encode
            encoded = ''
            encoded << encode_client_id
            encoded << [name.length * 2].pack('v')
            encoded << encode_name

            encoded
          end

          private

          # Encodes the client_id attribute
          #
          # @return [String]
          def encode_client_id
            file_time = (client_id.to_i + 11644473600) * 10000000
            encoded = ''
            encoded << [file_time].pack('Q<')

            encoded
          end

          # Encodes the name attribute
          #
          # @return [String]
          def encode_name
            Rex::Text.to_unicode(name)
          end
        end
      end
    end
  end
end