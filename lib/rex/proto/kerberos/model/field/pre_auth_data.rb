module Rex
  module Proto
    module Kerberos
      module Model
        module Field
          class PreAuthData < Element

            # @!attribute type
            #   @return [Fixnum] The padata type
            attr_accessor :type
            # @!attribute value
            #   @return [String] The padata value
            attr_accessor :value

            # Decodes a Rex::Proto::Kerberos::Model::Field::PreAuthData
            #
            # @param input [String, OpenSSL::ASN1::Sequence] the input to decode from
            # @return [self] if decoding succeeds
            # @raise [RuntimeError] if decoding doesn't succeed
            def decode(input)
              case input
              when String
                decode_string(input)
              when OpenSSL::ASN1::Sequence
                decode_asn1(input)
              else
                raise ::RuntimeError, 'Failed to decode PreAuthData, invalid input'
              end

              self
            end

            def encode
              raise ::RuntimeError, 'PreAuthData encoding unsupported'
            end

            private

            # Decodes a Rex::Proto::Kerberos::Model::Field::PreAuthData
            #
            # @param input [String] the input to decode from
            def decode_string(input)
              asn1 = OpenSSL::ASN1.decode(input)

              decode_asn1(asn1)
            end

            # Decodes a Rex::Proto::Kerberos::Model::Type::PreAuthData from an
            # OpenSSL::ASN1::Sequence
            #
            # @param input [OpenSSL::ASN1::Sequence] the input to decode from
            def decode_asn1(input)
              seq_values = input.value
              self.type  = decode_asn1_type(seq_values[0])
              self.value = decode_asn1_value(seq_values[1])
            end

            # Decodes the type from an OpenSSL::ASN1::ASN1Data
            #
            # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
            # @return [Fixnum]
            def decode_asn1_type(input)
              input.value[0].value.to_i
            end

            # Decodes the value from an OpenSSL::ASN1::ASN1Data
            #
            # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
            # @return [Fixnum]
            def decode_asn1_value(input)
              input.value[0].value
            end
          end
        end
      end
    end
  end
end