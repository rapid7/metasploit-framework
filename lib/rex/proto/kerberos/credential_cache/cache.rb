# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module CredentialCache
        # This class provides a representation of a Kerberos Credential Cache.
        class Cache < Element

          # @!attribute version
          #   @return [Integer] The file format version
          attr_accessor :version
          # @!attribute headers
          #   @return [Array<String>] The header tags
          attr_accessor :headers
          # @!attribute primary_principal
          #   @return [Rex::Proto::Kerberos::CredentialCache::Principal] The principal cache's owner
          attr_accessor :primary_principal
          # @!attribute credentials
          #   @return [Array<Rex::Proto::Kerberos::CredentialCache::Credential>] The primary principal credentials
          attr_accessor :credentials

          # Encodes the Rex::Proto::Kerberos::CredentialCache::Cache into an String
          #
          # @return [String] encoded cache
          def encode
            encoded = ''
            encoded << encode_version
            encoded << encode_headers
            encoded << encode_primary_principal
            encoded << encode_credentials
          end

          private

          # Encodes the version field
          #
          # @return [String]
          def encode_version
            [version].pack('n')
          end

          # Encodes the headers field
          #
          # @return [String]
          def encode_headers
            headers_encoded = ''
            headers_encoded << [headers.length].pack('n')
            headers.each do |h|
              headers_encoded << h
            end

            encoded = ''
            encoded << [headers_encoded.length].pack('n')
            encoded << headers_encoded

            encoded
          end

          # Encodes the primary_principal field
          #
          # @return [String]
          def encode_primary_principal
            primary_principal.encode
          end

          # Encodes the credentials field
          #
          # @return [String]
          def encode_credentials
            encoded = ''
            credentials.each do |cred|
              encoded << cred.encode
            end
            encoded
          end
        end
      end
    end
  end
end
