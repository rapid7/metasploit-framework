# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module CredentialCache
        # This class provides a representation of credential times stored in the Kerberos Credential Cache.
        class Time < Element
          # @!attribute auth_time
          #   @return [Integer]
          attr_accessor :auth_time
          # @!attribute start_time
          #   @return [Integer]
          attr_accessor :start_time
          # @!attribute end_time
          #   @return [Integer]
          attr_accessor :end_time
          # @!attribute renew_till
          #   @return [Integer]
          attr_accessor :renew_till

          # Encodes the Rex::Proto::Kerberos::CredentialCache::Time into an String
          #
          # @return [String] encoded time
          def encode
            encoded = ''
            encoded << encode_auth_time
            encoded << encode_start_time
            encoded << encode_end_time
            encoded << encode_renew_time

            encoded
          end

          private

          # Encodes the auth_time field
          #
          # @return [String]
          def encode_auth_time
            [auth_time].pack('N')
          end

          # Encodes the start_time field
          #
          # @return [String]
          def encode_start_time
            [start_time].pack('N')
          end

          # Encodes the end_time field
          #
          # @return [String]
          def encode_end_time
            [end_time].pack('N')
          end

          # Encodes the renew_time field
          #
          # @return [String]
          def encode_renew_time
            [renew_till].pack('N')
          end

        end
      end
    end
  end
end