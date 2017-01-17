# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module CredentialCache

        # This class provides a representation of a credential keys stored in the Kerberos Credential Cache.
        class KeyBlock < Element
          # @!attribute key_type
          #   @return [Integer]
          attr_accessor :key_type
          # @!attribute e_type
          #   @return [Integer]
          attr_accessor :e_type
          # @!attribute key_value
          #   @return [String]
          attr_accessor :key_value

          # Encodes the Rex::Proto::Kerberos::CredentialCache::KeyBlock into an String
          #
          # @return [String] encoded key
          def encode
            encoded = ''
            encoded << encode_key_type
            encoded << encode_e_type
            encoded << encode_key_value

            encoded
          end

          private

          # Encodes the key_type field
          #
          # @return [String]
          def encode_key_type
            [key_type].pack('n')
          end

          # Encodes the e_type field
          #
          # @return [String]
          def encode_e_type
            [e_type].pack('n')
          end

          # Encodes the key_value field
          #
          # @return [String]
          def encode_key_value
            encoded = ''
            encoded << [key_value.length].pack('n')
            encoded << key_value

            encoded
          end
        end
      end
    end
  end
end
