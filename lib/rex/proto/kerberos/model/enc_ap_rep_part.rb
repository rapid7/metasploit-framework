# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of an EncAPRepPart, sent as the
        # encrypted part of an AP-REP message
        class EncApRepPart < Element
          # @!attribute ctime
          #   @return [Time] The current time of the client's host
          attr_accessor :ctime
          # @!attribute cusec
          #   @return [Integer] The microsecond part of the client's timestamp
          attr_accessor :cusec
          # @!attribute subkey
          #   @return [Rex::Proto::Kerberos::Model::EncryptionKey] the client's choice for an encryption
          #   key which is to be used to protect this specific application session
          attr_accessor :subkey
          # @!attribute sequence_number
          #   @return [Integer] The initial sequence number to be used for future communications
          attr_accessor :sequence_number
          # @!attribute enc_key_usage
          #   @return [Rex::Proto::Kerberos::Crypto::KeyUsage,Integer] The enc key usage number for this object
          attr_accessor :enc_key_usage

          # Decodes the Rex::Proto::Kerberos::Model::EncApRepPart from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode EncApRepPart, invalid input'
            end

            self
          end

          # Encodes the Rex::Proto::Kerberos::Model::EncApReqPart into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_ctime], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_cusec], 1, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_subkey], 2, :CONTEXT_SPECIFIC) if subkey
            elems << OpenSSL::ASN1::ASN1Data.new([encode_sequence_number], 3, :CONTEXT_SPECIFIC) if sequence_number

            seq = OpenSSL::ASN1::Sequence.new(elems)
            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], ENC_AP_REP_PART, :APPLICATION)

            seq_asn1.to_der
          end

          # Encrypts the Rex::Proto::Kerberos::Model::EncApRepPart
          #
          # @param etype [Integer] the crypto schema to encrypt
          # @param key [String] the key to encrypt
          # @return [String] the encrypted result
          # @raise [NotImplementedError] if the encryption schema isn't supported
          def encrypt(etype, key)
            raise ::Rex::Proto::Kerberos::Model::Error::KerberosError, 'Missing enc_key_usage' unless enc_key_usage

            data = self.encode
            encryptor = Rex::Proto::Kerberos::Crypto::Encryption::from_etype(etype)
            encryptor.encrypt(data, key, enc_key_usage)
          end

          private

          # Encodes the cusec field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_cusec
            bn = OpenSSL::BN.new(cusec.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the ctime field
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_ctime
            OpenSSL::ASN1::GeneralizedTime.new(ctime)
          end

          # Encodes the subkey field
          #
          # @return [String]
          def encode_subkey
            subkey.encode
          end

          # Encodes the sequence_number field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_sequence_number
            bn = OpenSSL::BN.new(sequence_number.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncApRepPart from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncApRepPart
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 0
                self.ctime = decode_ctime(val)
              when 1
                self.cusec = decode_cusec(val)
              when 2
                self.subkey = decode_subkey(val)
              when 3
                self.sequence_number = decode_sequence_number(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Failed to decode EncApRepPart SEQUENCE (#{val.tag})"
              end
            end
          end

          # Decodes the ctime field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Time]
          def decode_ctime(input)
            input.value[0].value
          end

          # Decodes the cusec field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_cusec(input)
            input.value[0].value
          end

          # Decodes the sequence_number field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_sequence_number(input)
            input.value[0].value.to_i
          end

          # Decodes the subkey field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_subkey(input)
            Rex::Proto::Kerberos::Model::EncryptionKey::decode(input.value[0])
          end
        end
      end
    end
  end
end
