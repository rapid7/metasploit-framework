# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos KERB-SUPERSEDED-BY-USER
        # message as defined in [MS-KILE 2.2.13](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/79170b21-ad15-4a1b-99c4-84b3992d9e70).
        class KerbSupersededByUser < Element

          attr_accessor :principal_name

          attr_accessor :realm

          def ==(other)
            realm == other.realm && principal_name == other.principal_name
          end

          def to_s
            "#{principal_name}@#{realm}"
          end

          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::Sequence
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode KerbSupersededByUser, invalid input'
            end

            self
          end

          def encode
            principal_name_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_principal_name], 1, :CONTEXT_SPECIFIC)
            realm_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_realm], 2, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new([principal_name_asn1, realm_asn1])

            seq.to_der
          end

          private

          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::KerbSupersededByUser from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          def decode_asn1(input)
            seq_values = input.value
            self.principal_name = decode_principal_name(seq_values[0])
            self.realm = decode_realm(seq_values[1])
          end

         def decode_principal_name(input)
           PrincipalName.decode(input.value[0])
          end

          # Decodes the realm from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Array<String>]
          def decode_realm(input)
            input.value[0].value
          end

          def encode_principal_name
            self.principal_name.encode
          end

          def encode_realm
            OpenSSL::ASN1::OctetString.new(self.realm)
          end
        end
      end
    end
  end
end
