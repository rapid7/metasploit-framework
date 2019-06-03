# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos ticket that helps
        # a client authenticate to a service.
        class Ticket < Element
          # @!attribute tkt_vno
          #   @return [Integer] The ticket version number
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
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_tkt_vno], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_realm], 1, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_sname], 2, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_enc_part], 3, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], TICKET, :APPLICATION)

            seq_asn1.to_der
          end

          private

          # Encodes the tkt_vno field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_tkt_vno
            bn = OpenSSL::BN.new(tkt_vno.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the realm field
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_realm
            OpenSSL::ASN1::GeneralString.new(realm)
          end

          # Encodes the sname field
          #
          # @return [String]
          def encode_sname
            sname.encode
          end

          # Encodes the enc_part field
          #
          # @return [String]
          def encode_enc_part
            enc_part.encode
          end

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
          # @return [Integer]
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