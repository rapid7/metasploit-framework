# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Field
          # This class is a representation of a PA-ENC-TIMESTAMP, an encrypted timestamp
          class PreAuthEncTimeStamp < Element

            # @!attribute pa_time_stamp
            #   @return [Time] client's time
            attr_accessor :pa_time_stamp
            # @!attribute pausec
            #   @return [Fixnum] optional microseconds client's time
            attr_accessor :pausec

            # Decodes a Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp
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
                raise ::RuntimeError, 'Failed to decode EncryptedData Name, invalid input'
              end

              self
            end

            def encode
              raise ::RuntimeError, 'EncryptedData encoding is not supported'
            end

            # Decrypts a Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp
            #
            # @param input [String, OpenSSL::ASN1::Sequence] the input to decrypt from
            # @return [Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp] if decryption succeeds
            # @raise [RuntimeError] if decryption doesn't succeed
            def self.decrypt(input, key)
              elem = PreAuthEncTimeStamp.new
              elem.decrypt(input, key)

              elem
            end

            # Decrypts a Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp
            #
            # @param input [String, OpenSSL::ASN1::Sequence] the input to decrypt from
            # @return [self] if decryption succeeds
            # @raise [RuntimeError] if decryption doesn't succeed
            def decrypt(input, key)
              ed = Rex::Proto::Kerberos::Model::Type::EncryptedData.decode(input)
              decrypted = ed.decrypt(key, 1)
              decode(decrypted[8, decrypted.length - 1])

              self
            end

            private

            # Decodes a Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp
            #
            # @param input [String] the input to decode from
            def decode_string(input)
              asn1 = OpenSSL::ASN1.decode(input)

              decode_asn1(asn1)
            end

            # Decodes a Rex::Proto::Kerberos::Model::Type::PreAuthEncTimeStamp from an
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
            # @return [Fixnum]
            def decode_pausec(input)
              input.value[0].value.to_i
            end
          end
        end
      end
    end
  end
end