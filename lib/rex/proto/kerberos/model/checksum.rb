# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos Checksum definition.
        class Checksum < Element

          # @!attribute type
          #   @return [Integer] The algorithm used to generate the checksum
          attr_accessor :type
          # @!attribute checksum
          #   @return [String] The checksum itself
          attr_accessor :checksum

          # Decodes the Rex::Proto::Kerberos::Model::Checksum from an input
          #
          # @param input [String, OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::ASN1Data
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode Checksum, invalid input'
            end

            self
          end

          # Encodes a Rex::Proto::Kerberos::Model::Checksum into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_type], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_checksum], 1, :CONTEXT_SPECIFIC)

            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq.to_der
          end

          private

          # Encodes the type field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_type
            bn = OpenSSL::BN.new(type.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the checksum field
          #
          # @return [OpenSSL::ASN1::OctetString]
          def encode_checksum
            OpenSSL::ASN1::OctetString.new(checksum)
          end

          # Decodes a Rex::Proto::Kerberos::Model::Checksum from an String
          #
          # @param input [String] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          rescue OpenSSL::ASN1::ASN1Error
            raise Rex::Proto::Kerberos::Model::Error::KerberosDecodingError
          end

          # Decodes a Rex::Proto::Kerberos::Model::Checksum from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            seq_values = input.value

            seq_values.each do |val|
              case val.tag
              when 0
                self.type = decode_type(val)
              when 1
                self.checksum = decode_checksum(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode KdcRequestBody SEQUENCE'
              end
            end
          end

          # Decodes the type field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_type(input)
            input.value[0].value.to_i
          end

          # Decodes the checksum field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_checksum(input)
            input.value[0].value
          end

        end
      end
    end
  end
end
