# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of an encrypted message.
        class EncryptedData < Element
          # @!attribute name_type
          #   @return [Integer] The encryption algorithm
          attr_accessor :etype
          # @!attribute kvno
          #   @return [Integer] The version number of the key
          attr_accessor :kvno
          # @!attribute cipher
          #   @return [String] The enciphered text
          attr_accessor :cipher

          def ==(other)
            etype == other.etype &&
              kvno == other.kvno &&
              cipher == other.cipher
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncryptedData
          #
          # @param input [String, OpenSSL::ASN1::Sequence] the input to decode from
          # @return [self]
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::Sequence
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode EncryptedData Name, invalid input'
            end

            self
          end

          # Encodes a Rex::Proto::Kerberos::Model::EncryptedData into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []
            etype_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_etype], 0, :CONTEXT_SPECIFIC)
            elems << etype_asn1

            if kvno
              kvno_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_kvno], 1, :CONTEXT_SPECIFIC)
              elems << kvno_asn1
            end

            cipher_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_cipher], 2, :CONTEXT_SPECIFIC)
            elems << cipher_asn1

            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq.to_der
          end

          # Decrypts the cipher with etype encryption schema, presuming that the
          # data is an ASN1 structure
          #
          # @param key [String] the key to decrypt
          # @param msg_type [Integer] the message type
          # @return [String] the decrypted `cipher`
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decryption doesn't succeed
          # @raise [NotImplementedError] if encryption isn't supported
          def decrypt_asn1(key, msg_type)
            if cipher.nil? || cipher.empty?
              return ''
            end

            encryptor = Rex::Proto::Kerberos::Crypto::Encryption::from_etype(etype)
            encryptor.decrypt_asn1(cipher, key, msg_type)
          end


          private

          # Encodes the etype
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_etype
            bn = OpenSSL::BN.new(etype.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the kvno
          #
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError]
          def encode_kvno
            bn = OpenSSL::BN.new(kvno.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          rescue OpenSSL::ASN1::ASN1Error
            raise Rex::Proto::Kerberos::Model::Error::KerberosDecodingError
          end

          # Encodes the cipher
          #
          # @return [OpenSSL::ASN1::OctetString]
          def encode_cipher
            OpenSSL::ASN1::OctetString.new(cipher)
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncryptedData from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncryptedData from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            seq_values = input.value

            seq_values.each do |val|
              case val.tag
              when 0
                self.etype = decode_etype(val)
              when 1
                self.kvno = decode_kvno(val)
              when 2
                self.cipher = decode_cipher(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode EncryptedData SEQUENCE'
              end
            end
          end

          # Decodes the etype from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_etype(input)
            input.value[0].value.to_i
          end

          # Decodes the kvno from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
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
