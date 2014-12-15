# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        class Ticket < Element
          # @!attribute tkt_vno
          #   @return [Fixnum] The ticket version number
          attr_accessor :tkt_vno
          # @!attribute realm
          #   @return [String] The realm that issued the ticket
          attr_accessor :realm
          # @!attribute sname
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName] The name part of the server's identity
          attr_accessor :sname
          # @!attribute enc_part
          #   @return [Rex::Proto::Kerberos::Model::EncryptedData] The encrypted part of the ticket
          attr_accessor :enc_part

          # Decodes the Rex::Proto::Kerberos::Model::KrbError from an input
          #
          # @param input [String, OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [RuntimeError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::ASN1Data
              decode_asn1(input)
            else
              raise ::RuntimeError, 'Failed to decode Ticket, invalid input'
            end

            self
          end

          def encode
            raise ::RuntimeError, 'Ticket encoding not supported'
          end

          private

          # Decodes a Rex::Proto::Kerberos::Model::Ticket from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::Ticket
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [RuntimeError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 0
                self.tkt_vno = decode_tkt_vno(val)
              when 1
                self.realm = decode_realm(val)
              when 2
                self.sname = decode_sname(val)
              when 3
                self.enc_part = decode_enc_part(val)
              else
                raise ::RuntimeError, 'Failed to decode Ticket SEQUENCE'
              end
            end
          end

          # Decodes the tkt_vno from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Fixnum]
          def decode_tkt_vno(input)
            input.value[0].value.to_i
          end

          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_realm(input)
            input.value[0].value
          end

          # Decodes the sname field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::PrincipalName]
          def decode_sname(input)
            Rex::Proto::Kerberos::Model::PrincipalName.decode(input.value[0])
          end

          # Decodes the enc_part from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::EncryptedData]
          def decode_enc_part(input)
            Rex::Proto::Kerberos::Model::EncryptedData.decode(input.value[0])
          end
        end
      end
    end
  end
end