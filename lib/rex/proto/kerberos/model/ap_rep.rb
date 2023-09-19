# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos AP-REP (response) data
        # definition
        class ApRep < Element
          # @!attribute pvno
          #   @return [Integer] The protocol version number
          attr_accessor :pvno
          # @!attribute msg_type
          #   @return [Integer] The type of a protocol message
          attr_accessor :msg_type
          # @!attribute enc_part
          #   @return [Rex::Proto::Kerberos::Model::EncryptedData] The encrypted part of the response
          attr_accessor :enc_part

          # Decodes the Rex::Proto::Kerberos::Model::ApRep from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode ApRep, invalid input'
            end

            self
          end

          # Encodes the Rex::Proto::Kerberos::Model::ApReq into an ASN.1 String
          #
          # @return [String]
          def encode
            to_asn1.to_der
          end

          # @return [OpenSSL::ASN1::ASN1Data] The ap_req ASN1Data
          def to_asn1
            elems = []

            elems << OpenSSL::ASN1::ASN1Data.new([encode_pvno], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_msg_type], 1, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_enc_part], 2, :CONTEXT_SPECIFIC)

            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], AP_REP, :APPLICATION)
            seq_asn1
          end

          def decrypt_enc_part(key)
            data = enc_part.decrypt_asn1(key, Rex::Proto::Kerberos::Crypto::KeyUsage::AP_REP_ENCPART)

            result = Rex::Proto::Kerberos::Model::EncApRepPart::decode(data)
          end

          private

          # Encodes the pvno field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_pvno
            bn = OpenSSL::BN.new(pvno.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the msg_type field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_msg_type
            bn = OpenSSL::BN.new(msg_type.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the enc_part field
          #
          # @return [String]
          def encode_enc_part
            enc_part.encode
          end

          # Decodes a Rex::Proto::Kerberos::Model::ApRep from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::ApRep
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 0
                self.pvno = decode_pvno(val)
              when 1
                self.msg_type = decode_msg_type(val)
              when 2
                self.enc_part = decode_enc_part(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Failed to decode AP-REP SEQUENCE (#{val.tag})"
              end
            end
          end

          # Decodes the pvno from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_pvno(input)
            input.value[0].value.to_i
          end

          # Decodes the msg_type from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_msg_type(input)
            input.value[0].value.to_i
          end

          # Decodes the enc_part
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
