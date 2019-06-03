# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a principal, an asset (e.g., a
        # workstation user or a network server) on a network.
        class PrincipalName < Element

          # @!attribute name_type
          #   @return [Integer] The type of name
          attr_accessor :name_type
          # @!attribute name_string
          #   @return [Array<String>] A sequence of strings that form a name.
          attr_accessor :name_string

          # Decodes a Rex::Proto::Kerberos::Model::PrincipalName
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
              raise ::RuntimeError, 'Failed to decode Principal Name, invalid input'
            end

            self
          end

          # Encodes a Rex::Proto::Kerberos::Model::PrincipalName into an
          # ASN.1 String
          #
          # @return [String]
          def encode
            integer_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_name_type], 0, :CONTEXT_SPECIFIC)
            string_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_name_string], 1, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new([integer_asn1, string_asn1])

            seq.to_der
          end

          private

          # Encodes the name_type
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_name_type
            int_bn = OpenSSL::BN.new(name_type.to_s)
            int = OpenSSL::ASN1::Integer.new(int_bn)

            int
          end

          # Encodes the name_string
          #
          # @return [OpenSSL::ASN1::Sequence]
          def encode_name_string
            strings = []
            name_string.each do |s|
              strings << OpenSSL::ASN1::GeneralString.new(s)
            end
            seq_string = OpenSSL::ASN1::Sequence.new(strings)

            seq_string
          end

          # Decodes a Rex::Proto::Kerberos::Model::PrincipalName from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PrincipalName from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          def decode_asn1(input)
            seq_values = input.value
            self.name_type = decode_name_type(seq_values[0])
            self.name_string = decode_name_string(seq_values[1])
          end

          # Decodes the name_type from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_name_type(input)
            input.value[0].value.to_i
          end

          # Decodes the name_string from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Array<String>]
          def decode_name_string(input)
            strings = []
            input.value[0].value.each do |v|
              strings << v.value
            end

            strings
          end
        end
      end
    end
  end
end