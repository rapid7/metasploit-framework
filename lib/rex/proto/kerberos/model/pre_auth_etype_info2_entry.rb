# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a PA-Etype-Info2-Entry structure,
        # which contains information about valid encryption types and salts 
        # that can be used to authenticate using Kerberos Pre-Authentication
        class PreAuthEtypeInfo2Entry < Element
          # @!attribute etype
          #   @return [Integer] The supported encryption type
          attr_accessor :etype
          # @!attribute salt
          #   @return [String] The salt that should be used with this encryption type
          attr_accessor :salt
          # @!attribute s2kparams
          #   @return [String] An encryption type-specific parameter
          attr_accessor :s2kparams

          # Decodes the Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2Entry from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode ETYPE-INFO2, invalid input'
            end

            self
          end

          # Encodes a Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2Entry into an ASN.1 String
          #
          # @return [String]
          def encode
            result = []
            result << OpenSSL::ASN1::ASN1Data.new([encode_etype], 0, :CONTEXT_SPECIFIC)
            result << OpenSSL::ASN1::ASN1Data.new([encode_salt], 1, :CONTEXT_SPECIFIC) if self.salt
            result << OpenSSL::ASN1::ASN1Data.new([encode_s2kparams], 2, :CONTEXT_SPECIFIC) if self.s2kparams
            seq = OpenSSL::ASN1::Sequence.new(result)

            seq.to_der
          end

          private

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2Entry from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2Entry
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value.each do |val|
              case val.tag
              when 0
                self.etype = decode_etype(val)
              when 1
                self.salt = decode_salt(val)
              when 2
                self.s2kparams = decode_s2kparams(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Failed to decode EType-Info2-Entry SEQUENCE (#{val.tag})"
              end
            end
          end

          # Decodes the etype from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_etype(input)
            input.value[0].value.to_i
          end

          # Decodes the salt from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_salt(input)
            input.value[0].value
          end

          # Decodes the s2kparams from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_s2kparams(input)
            input.value[0].value
          end

          # Encodes the etype
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_etype
            int_bn = OpenSSL::BN.new(self.etype.to_s)
            int = OpenSSL::ASN1::Integer.new(int_bn)
          end

          # Encodes the salt
          #
          # @return [OpenSSL::ASN1::OctetString]
          def encode_salt
            OpenSSL::ASN1::GeneralString.new(self.salt)
          end

          # Encodes the parms
          #
          # @return [OpenSSL::ASN1::OctetString]
          def encode_s2kparams
            OpenSSL::ASN1::OctetString.new(self.s2kparams)
          end

        end
      end
    end
  end
end
