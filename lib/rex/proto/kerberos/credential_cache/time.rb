module Rex
  module Proto
    module Kerberos
      module CredentialCache
        class Time < Element
          # Fixnum
          attr_accessor :auth_time
          # Fixnum
          attr_accessor :start_time
          # Fixnum
          attr_accessor :end_time
          # Fixnum
          attr_accessor :renew_till

          def encode
            encoded = ''
            encoded << encode_auth_time
            encoded << encode_start_time
            encoded << encode_end_time
            encoded << encode_renew_time

            encoded
          end

          private

          def encode_auth_time
            [auth_time].pack('N')
          end

          def encode_start_time
            [start_time].pack('N')
          end

          def encode_end_time
            [end_time].pack('N')
          end

          def encode_renew_time
            [renew_till].pack('N')
          end

        end
      end
    end
  end
end