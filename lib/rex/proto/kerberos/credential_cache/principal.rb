# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module CredentialCache
        # This class provides a representation of a Principal stored in the Kerberos Credential Cache.
        class Principal < Element
          # @!attribute name_type
          #   @return [Integer]
          attr_accessor :name_type
          # @!attribute realm
          #   @return [String]
          attr_accessor :realm
          # @!attribute components
          #   @return [Array<String>]
          attr_accessor :components

          # Encodes the Rex::Proto::Kerberos::CredentialCache::Principal into an String
          #
          # @return [String] encoded principal
          def encode
            encoded = ''
            encoded << encode_name_type
            encoded << [components.length].pack('N')
            encoded << encode_realm
            encoded << encode_components

            encoded
          end

          private

          # Encodes the name_type field
          #
          # @return [String]
          def encode_name_type
            [name_type].pack('N')
          end

          # Encodes the realm field
          #
          # @return [String]
          def encode_realm
            encoded = ''
            encoded << [realm.length].pack('N')
            encoded << realm

            encoded
          end

          # Encodes the components field
          #
          # @return [String]
          def encode_components
            encoded = ''

            components.each do |c|
              encoded << [c.length].pack('N')
              encoded << c
            end

            encoded
          end

        end
      end
    end
  end
end
