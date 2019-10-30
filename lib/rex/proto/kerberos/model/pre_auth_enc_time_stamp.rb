# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class is a representation of a PA-ENC-TIMESTAMP, an encrypted timestamp sent
        # as pre authenticated data
        class PreAuthEncTimeStamp < Element

          CRYPTO_MSG_TYPE = 1

          # @!attribute pa_time_stamp
          #   @return [Time] client's time
          attr_accessor :pa_time_stamp
          # @!attribute pausec
          #   @return [Integer] optional microseconds client's time
          attr_accessor :pausec

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthEncTimeStamp
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
              raise ::RuntimeError, 'Failed to decode PreAuthEncTimeStamp, invalid input'
            end

            self
          end

          # Encodes a Rex::Proto::Kerberos::Model::PreAuthEncTimeStamp into an
          # ASN.1 String
          #
          # @return [String]
          def encode
            pa_time_stamp_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_pa_time_stamp], 0, :CONTEXT_SPECIFIC)
            pausec_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_pausec], 1, :CONTEXT_SPECIFIC)
            seq = OpenSSL::ASN1::Sequence.new([pa_time_stamp_asn1, pausec_asn1])

            seq.to_der
          end

          # Encrypts the Rex::Proto::Kerberos::Model::PreAuthEncTimeStamp
          #
          # @param etype [Integer] the crypto schema to encrypt
          # @param key [String] the key to encrypt
          # @return [String] the encrypted result
          # @raise [NotImplementedError] if encryption schema isn't supported
          def encrypt(etype, key)
            data = self.encode

            res = ''
            case etype
            when RC4_HMAC
              res = encrypt_rc4_hmac(data, key, CRYPTO_MSG_TYPE)
            else
              raise ::NotImplementedError, 'EncryptedData schema is not supported'
            end

            res
          end

          private

          # Encodes the pa_time_stamp
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_pa_time_stamp
            OpenSSL::ASN1::GeneralizedTime.new(pa_time_stamp)
          end

          # Encodes the pausec
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_pausec
            int_bn = OpenSSL::BN.new(pausec.to_s)
            int = OpenSSL::ASN1::Integer.new(int_bn)

            int
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthEncTimeStamp
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthEncTimeStamp from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          def decode_asn1(input)
            self.pa_time_stamp = decode_pa_time_stamp(input.value[0])
            self.pausec = decode_pausec(input.value[1])
          end

          # Decodes the decode_pa_time_stamp from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Boolean]
          def decode_pa_time_stamp(input)
            input.value[0].value
          end

          # Decodes the pausec from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_pausec(input)
            input.value[0].value.to_i
          end
        end
      end
    end
  end
end