module Rex
  module Proto
    module Kerberos
      module CredentialCache
        class KeyBlock < Element
          #Fixnum
          attr_accessor :key_type
          # Fixnum
          attr_accessor :e_type
          # String
          attr_accessor :key_value

          def encode
            encoded = ''
            encoded << encode_key_type
            encoded << encode_e_type
            encoded << encode_key_value

            encoded
          end

          private

          def encode_key_type
            [key_type].pack('n')
          end

          def encode_e_type
            [e_type].pack('n')
          end

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
