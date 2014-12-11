# -*- coding: binary -*-

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
                raise ::RuntimeError, 'Failed to decode EncryptedData Name, invalid input'
              end

              self
            end

            # Encodes a Rex::Proto::Kerberos::Model::Type::EncryptedData into an ASN.1 String
            #
            # @return [String]
            # @raise [RuntimeError] if encoding doesn't succeed
            def encode
              seq = nil
              etype_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_etype], 0, :CONTEXT_SPECIFIC)
              if kvno
                kvno_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_kvno], 1, :CONTEXT_SPECIFIC)
                cipher_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_cipher], 2, :CONTEXT_SPECIFIC)
                seq = OpenSSL::ASN1::Sequence.new([etype_asn1, kvno_asn1, cipher_asn1])
              else
                cipher_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_cipher], 1, :CONTEXT_SPECIFIC)
                seq = OpenSSL::ASN1::Sequence.new([etype_asn1, cipher_asn1])
              end

              seq.to_der
            end

            # Decrypts the cipher with etype encryption schema
            #
            # @param key [String] the key to decrypt
            # @param key [Fixnum] the message type
            # @return [String] if decryption succeeds
            # @raise [RuntimeError] if decryption doesn't succeed
            def decrypt(key, msg_type)
              if cipher.nil? or cipher.empty?
                return ''
              end

              res = ''
              case etype
              when KERB_ETYPE_RC4_HMAC
                res = decrypt_rc4_hmac(key, msg_type)
              else
                raise ::RuntimeError, 'EncryptedData encoding is not supported'
              end

              res
            end

            private

            # Encodes the etype
            #
            # @return [OpenSSL::ASN1::Integer]
            def encode_etype
              bn = OpenSSL::BN.new(etype)
              int = OpenSSL::ASN1::Integer(bn)

              int
            end

            # Encodes the kvno (unsupported)
            #
            # @raise [RuntimeError]
            def encode_kvno
              raise RuntimeError, 'Encoding EncryptedData failed, kvno not supported'
            end

            # Encodes the cipher
            #
            # @return [OpenSSL::ASN1::OctetString]
            def encode_cipher
              OpenSSL::ASN1::OctetString.new(cipher)
            end

            # Decrypts the cipher using RC4-HMAC schema
            #
            # @param key [String] the key to decrypt
            # @param key [Fixnum] the message type
            # @return [String] if decryption succeeds
            # @raise [RuntimeError] if decryption doesn't succeed
            def decrypt_rc4_hmac(key, msg_type)
              unless cipher && cipher.length > 16
                raise ::RuntimeError, 'RC4-HMAC decryption failed'
              end

              my_key = OpenSSL::Digest.digest('MD4', Rex::Text.to_unicode(key))

              checksum = cipher[0, 16]
              data = cipher[16, cipher.length - 1]

              k1 = OpenSSL::HMAC.digest('MD5', my_key, [msg_type].pack('V'))
              k3 = OpenSSL::HMAC.digest('MD5', k1, checksum)

              cipher = OpenSSL::Cipher::Cipher.new("rc4")
              cipher.decrypt
              cipher.key = k3
              decrypted = cipher.update(data) + cipher.final

              if OpenSSL::HMAC.digest('MD5', k1, decrypted) != checksum
                raise ::RuntimeError, 'RC4-HMAC decryption failed, incorrect checksum verification'
              end

              decrypted
            end

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