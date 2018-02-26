# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation for Kerberos pre authenticated
        # data
        class PreAuthData < Element

          # @!attribute type
          #   @return [Integer] The padata type
          attr_accessor :type
          # @!attribute value
          #   @return [String] The padata value
          attr_accessor :value

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthData
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

          # Encodes a Rex::Proto::Kerberos::Model::PreAuthData into an ASN.1 String
          #
          # @return [String]
          def encode
            type_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_type], 1, :CONTEXT_SPECIFIC)
            value_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_value], 2, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new([type_asn1, value_asn1])

            seq.to_der
          end

          private

          # Encodes the type
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_type
            int_bn = OpenSSL::BN.new(type.to_s)
            int = OpenSSL::ASN1::Integer.new(int_bn)

            int
          end

          # Encodes the value
          #
          # @return [OpenSSL::ASN1::OctetString]
          def encode_value
            OpenSSL::ASN1::OctetString.new(value)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthData
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthData from an
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
          # @return [Integer]
          def decode_asn1_type(input)
            input.value[0].value.to_i
          end

          # Decodes the value from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_asn1_value(input)
            input.value[0].value
          end
        end
      end
    end
  end
end