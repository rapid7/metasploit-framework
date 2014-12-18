module Rex
  module Proto
    module Kerberos
      module CredentialCache
        class Credential < Element
          # Principal
          attr_accessor :client
          # Principal
          attr_accessor :server
          # KeyBlock
          attr_accessor :key
          # Time
          attr_accessor :time
          # Fixnum
          attr_accessor :is_skey
          # Fixnum
          attr_accessor :tkt_flags
          # Array
          attr_accessor :addrs
          # Array
          attr_accessor :auth_data
          # String
          attr_accessor :ticket
          # String
          attr_accessor :second_ticket

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
            encoded << second_ticket
          end

          private

          def encode_client
            client.encode
          end

          def encode_server
            server.encode
          end

          def encode_key
            key.encode
          end

          def encode_time
            time.encode
          end

          def encode_is_skey
            [is_skey].pack('C')
          end

          def encode_tkt_flags
            [tkt_flags].pack('N')
          end

          def encode_addrs
            encoded = ''
            if addrs.length > 0
              raise ::RuntimeError, 'CredentialCache: Credential addresses encoding not supported'
            end
            encoded << [addrs.length].pack('N')
            encoded
          end

          def encode_auth_data
            encoded = ''
            if auth_data.length > 0
              raise ::RuntimeError, 'CredentialCache: Credential auth_data encoding not supported'
            end
            encoded << [auth_data.length].pack('N')
            encoded
          end

          def encode_ticket
            encoded = ''
            encoded << [ticket.length].pack('N')
            encoded << ticket

            encoded
          end

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
