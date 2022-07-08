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

          def decode(input)
            raise ::NotImplementedError, 'EncApRepPart encoding not supported'
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
        end
      end
    end
  end
end
