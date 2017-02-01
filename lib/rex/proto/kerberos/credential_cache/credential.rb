# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module CredentialCache
        # This class provides a representation of a Credential stored in the Kerberos Credential Cache.
        class Credential < Element
          # @!attribute client
          #   @return [Rex::Proto::Kerberos::CredentialCache::Principal]
          attr_accessor :client
          # @!attribute server
          #   @return [Rex::Proto::Kerberos::CredentialCache::Principal]
          attr_accessor :server
          # @!attribute key
          #   @return [Rex::Proto::Kerberos::CredentialCache::KeyBlock]
          attr_accessor :key
          # @!attribute time
          #   @return [Rex::Proto::Kerberos::CredentialCache::Time]
          attr_accessor :time
          # @!attribute is_skey
          #   @return [Integer]
          attr_accessor :is_skey
          # @!attribute tkt_flags
          #   @return [Integer]
          attr_accessor :tkt_flags
          # @!attribute addrs
          #   @return [Array]
          attr_accessor :addrs
          # @!attribute auth_data
          #   @return [Array]
          attr_accessor :auth_data
          # @!attribute ticket
          #   @return [String]
          attr_accessor :ticket
          # @!attribute second_ticket
          #   @return [String]
          attr_accessor :second_ticket

          # Encodes the Rex::Proto::Kerberos::CredentialCache::Credential into an String
          #
          # @return [String] encoded credential
          def encode
            encoded = ''
            encoded << encode_client
            encoded << encode_server
            encoded << encode_key
            encoded << encode_time
            encoded << encode_is_skey
            encoded << encode_tkt_flags
            encoded << encode_addrs
            encoded << encode_auth_data
            encoded << encode_ticket
            encoded << encode_second_ticket
          end

          private

          # Encodes the client field
          #
          # @return [String]
          def encode_client
            client.encode
          end

          # Encodes the server field
          #
          # @return [String]
          def encode_server
            server.encode
          end

          # Encodes the key field
          #
          # @return [String]
          def encode_key
            key.encode
          end

          # Encodes the time field
          #
          # @return [String]
          def encode_time
            time.encode
          end

          # Encodes the is_skey field
          #
          # @return [String]
          def encode_is_skey
            [is_skey].pack('C')
          end

          # Encodes the tkt_flags field
          #
          # @return [String]
          def encode_tkt_flags
            [tkt_flags].pack('N')
          end

          # Encodes the addrs field
          #
          # @return [String]
          # @raise [NotImplementedError] if there are addresses to encode
          def encode_addrs
            encoded = ''
            if addrs.length > 0
              raise ::NotImplementedError, 'CredentialCache: Credential addresses encoding not supported'
            end
            encoded << [addrs.length].pack('N')
            encoded
          end

          # Encodes the auth_data field
          #
          # @return [String]
          def encode_auth_data
            encoded = ''
            if auth_data.length > 0
              raise ::RuntimeError, 'CredentialCache: Credential auth_data encoding not supported'
            end
            encoded << [auth_data.length].pack('N')
            encoded
          end

          # Encodes the ticket field
          #
          # @return [String]
          def encode_ticket
            encoded = ''
            encoded << [ticket.length].pack('N')
            encoded << ticket

            encoded
          end

          # Encodes the second_ticket field
          #
          # @return [String]
          def encode_second_ticket
            encoded = ''
            encoded << [second_ticket.length].pack('N')
            encoded << second_ticket

            encoded
          end
        end
      end
    end
  end
end
