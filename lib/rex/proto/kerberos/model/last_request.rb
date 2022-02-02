# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of request time
        class LastRequest < Element

          # @!attribute type
          #   @return [Integer] The type of value
          attr_accessor :type
          # @!attribute value
          #   @return [Time] the time of the last request
          attr_accessor :value

          # Decodes a Rex::Proto::Kerberos::Model::LastRequest
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
              raise ::RuntimeError, 'Failed to decode LastRequest, invalid input'
            end

            self
          end

          # Rex::Proto::Kerberos::Model::LastRequest encoding isn't supported
          #
          # @raise [NotImplementedError]
          def encode
            raise ::NotImplementedError, 'LastRequest encoding not supported'
          end

          private

          # Decodes a Rex::Proto::Kerberos::Model::LastReque from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncryptionKey from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          def decode_asn1(input)
            seq_values = input.value
            self.type = decode_type(seq_values[0])
            self.value = decode_value(seq_values[1])
          end

          # Decodes the key_type from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_type(input)
            input.value[0].value.to_i
          end

          # Decodes the value from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_value(input)
            input.value[0].value
          end
        end
      end
    end
  end
end