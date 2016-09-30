# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class is a representation of a KERB-PA-PAC-REQUEST, pre authenticated data to
        # explicitly request to include or exclude a PAC in the ticket.
        class PreAuthPacRequest < Element

          # @!attribute value
          #   @return [Boolean]
          attr_accessor :value

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthPacRequest
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
              raise ::RuntimeError, 'Failed to decode PreAuthPacRequest, invalid input'
            end

            self
          end

          # Encodes a Rex::Proto::Kerberos::Model::PreAuthPacRequest into an
          # ASN.1 String
          #
          # @return [String]
          def encode
            value_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_value], 0, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new([value_asn1])

            seq.to_der
          end

          private

          # Encodes value attribute
          #
          # @return [OpenSSL::ASN1::Boolean]
          def encode_value
            OpenSSL::ASN1::Boolean.new(value)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthPacRequest
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthPacRequest from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          def decode_asn1(input)
            self.value = decode_asn1_value(input.value[0])
          end

          # Decodes the value from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Boolean]
          def decode_asn1_value(input)
            input.value[0].value
          end
        end
      end
    end
  end
end