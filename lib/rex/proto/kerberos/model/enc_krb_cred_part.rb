# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of an EncKrbCredPart, sent as the
        # encrypted part of a KRB-CRED
        class EncKrbCredPart < Element
          # @!attribute ticket-info
          #   @return [Array<Rex::Proto::Kerberos::Model::KrbCredInfo>] The information corresponding to tickets in a KrbCred object
          attr_accessor :ticket_info

          # Decodes the Rex::Proto::Kerberos::Model::EncKrbCredPart from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode EncKrbCredPart, invalid input'
            end

            self
          end

          def encrypt(key)
            encryptor = Rex::Proto::Kerberos::Crypto::Encryption.from_etype(key.type)
            data = encryptor.encrypt(encode, key.value, Rex::Proto::Kerberos::Crypto::KeyUsage::KRB_CRED_ENCPART)

            result = Rex::Proto::Kerberos::Model::EncryptedData.new(
              etype: key.type,
              cipher: data
            )
          end

          # Encodes the Rex::Proto::Kerberos::Model::EncApRepPart into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_ticket_info], 0, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new(elems)
            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], ENC_KRB_CRED_PART, :APPLICATION)

            seq_asn1.to_der
          end

          private

          # Encodes the ticket_info field
          #
          # @return [OpenSSL::ASN1::Sequence]
          def encode_ticket_info
            encoded = ticket_info.map {|t| t.encode }
            seq = OpenSSL::ASN1::Sequence.new(encoded)
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncKrbCredPart from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncKrbCredPart
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 0
                self.ticket_info = decode_krb_cred_infos(val)
              when 1, 2, 3, 4, 5
                ilog "Ignoring optional value #{val.tag} while decoding EncKrbCredPart"
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode EncKrbCredPart SEQUENCE'
              end
            end
          end

          # Decodes the tickets from an OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          # @return [Array<Rex::Proto::Kerberos::Model::KrbCred>]
          def decode_krb_cred_infos(input)
            krb_creds = []
            input.value.each do |val|
              krb_creds << Rex::Proto::Kerberos::Model::KrbCredInfo.decode(val.value[0])
            end
            krb_creds
          end
        end
      end
    end
  end
end
