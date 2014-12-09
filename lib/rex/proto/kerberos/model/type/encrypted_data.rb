module Rex
  module Proto
    module Kerberos
      module Model
        module Type
          # This class provides a representation of an encrypted message.
          class EncryptedData < Element

            # @!attribute name_type
            #   @return [Fixnum] The encryption algorithm
            attr_accessor :etype
            # @!attribute kvno
            #   @return [Fixnum] The version number of the key
            attr_accessor :kvno
            # @!attribute cipher
            #   @return [String] The enciphered text
            attr_accessor :cipher

            # Decodes a Rex::Proto::Kerberos::Model::Type::EncryptedData
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
                raise ::RuntimeError, 'Failed to decode Principal Name, invalid input'
              end

              self
            end

            private

            # Decodes a Rex::Proto::Kerberos::Model::Type::EncryptedData from an String
            #
            # @param input [String] the input to decode from
            def decode_string(input)
              asn1 = OpenSSL::ASN1.decode(input)

              decode_asn1(asn1)
            end

            # Decodes a Rex::Proto::Kerberos::Model::Type::EncryptedData from an
            # OpenSSL::ASN1::Sequence
            #
            # @param input [OpenSSL::ASN1::Sequence] the input to decode from
            # @raise [RuntimeError] if decoding doesn't succeed
            def decode_asn1(input)
              seq_values = input.value
              self.etype = decode_etype(seq_values[0])
              case seq_values[1].value[0]
              when OpenSSL::ASN1::Integer
                self.kvno = decode_kvno(seq_values[1])
                self.cipher = decode_cipher(seq_values[2])
              when OpenSSL::ASN1::OctetString
                self.cipher = decode_cipher(seq_values[1])
              else
                raise ::RuntimeError, 'Failed to decode EncryptedData ASN1 Sequence'
              end
            end

            # Decodes the etype from an OpenSSL::ASN1::ASN1Data
            #
            # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
            # @return [Fixnum]
            def decode_etype(input)
              input.value[0].value.to_i
            end

            # Decodes the kvno from an OpenSSL::ASN1::ASN1Data
            #
            # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
            # @return [Fixnum]
            def decode_kvno(input)
              input.value[0].value.to_i
            end

            # Decodes the cipher from an OpenSSL::ASN1::ASN1Data
            #
            # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
            # @return [Sting]
            def decode_cipher(input)
              input.value[0].value
            end

          end
        end
      end
    end
  end
end