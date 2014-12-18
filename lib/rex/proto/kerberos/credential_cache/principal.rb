module Rex
  module Proto
    module Kerberos
      module CredentialCache
=begin
          uint32_t name_type;           /* not present if version 0x0501 */
          uint32_t num_components;      /* sub 1 if version 0x501 */
          counted_octet_string realm;
          counted_octet_string components[num_components];
=end
        class Principal < Element
          # Fixnum
          attr_accessor :name_type
          # String
          attr_accessor :realm
          # Array<String>
          attr_accessor :components


          def encode
            encoded = ''
            encoded << encode_name_type
            encoded << [components.length].pack('N')
            encoded << encode_realm
            encoded << encode_components

            encoded
          end

          private

          def encode_name_type
            #NT_PRINCIPAL = 1
            [name_type].pack('N')
          end

          def encode_realm
            encoded = ''
            encoded << [realm.length].pack('N')
            encoded << realm

            encoded
          end

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
