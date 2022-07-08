# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos KRB-CRED
        # message definition.
        class KrbCred < Element
          # @!attribute pvno
          #   @return [Integer] The protocol version number
          attr_accessor :pvno
          # @!attribute msg_type
          #   @return [Integer] The type of a protocol message
          attr_accessor :msg_type
          # @!attribute tickets
          #   @return [Array<Rex::Proto::Kerberos::Model::Ticket>] Tickets encapsulated in this message
          attr_accessor :tickets
          # @!attribute enc_part
          #   @return [Rex::Proto::Kerberos::Model::EncryptedData] Encrypted KRB-CRED blob
          attr_accessor :enc_part

          # Decodes the Rex::Proto::Kerberos::Model::KrbCred from an input
          #
          # @param input [String, OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            raise ::NotImplementedError, 'KrbCred decoding not supported'
          end

          # Rex::Proto::Kerberos::Model::KrbCred encoding isn't supported
          #
          # @raise [NotImplementedError]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_pvno], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_msg_type], 1, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_tickets], 2, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_enc_part], 3, :CONTEXT_SPECIFIC)

            seq = OpenSSL::ASN1::Sequence.new(elems)
            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], KRB_CRED, :APPLICATION)

            seq_asn1.to_der
          end

          private

          # Encodes the pvno
          #
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError]
          def encode_pvno
            bn = OpenSSL::BN.new(pvno.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          rescue OpenSSL::ASN1::ASN1Error
            raise Rex::Proto::Kerberos::Model::Error::KerberosDecodingError
          end

          # Encodes the msg_type field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_msg_type
            bn = OpenSSL::BN.new(msg_type.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the ticket field
          #
          # @return [OpenSSL::ASN1::Sequence]
          def encode_tickets
            encoded = tickets.map {|t| t.encode}
            seq = OpenSSL::ASN1::Sequence.new(encoded)
          end

          # Encodes the enc_part field
          #
          # @return [String]
          def encode_enc_part
            encoded = enc_part.encode
          end

        end
      end
    end
  end
end
