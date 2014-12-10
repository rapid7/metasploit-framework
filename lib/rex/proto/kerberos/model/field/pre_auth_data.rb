module Rex
  module Proto
    module Kerberos
      module Model
        module Field
          class PreAuthData < Element
            attr_accessor :type
            attr_accessor :value

            def decode(input)
              case input
              when String
                decode_string(input)
              when OpenSSL::ASN1::Sequence
                decode_asn1(input)
              else
                raise ::RuntimeError, 'Failed to decode Principal Name, invalid input'
              end

              self
            end

            def encode
              raise ::RuntimeError, 'PreAuthData encoding unsupported'
            end

            private

            def decode_string(input)
              asn1 = OpenSSL::ASN1.decode(input)

              decode_asn1(asn1)
            end

            def decode_asn1(input)
              seq_values = input.value
              self.type  = decode_asn1_type(seq_values[0])
              self.value = decode_asn1_value(seq_values[1])
            end

            def decode_asn1_type(input)
              input.value[0].value.to_i
            end

            def decode_asn1_value(input)
              input.value[0].value
            end
          end
        end
      end
    end
  end
end