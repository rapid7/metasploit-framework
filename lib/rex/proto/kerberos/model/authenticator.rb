# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        class Authenticator < Element
          include Rex::Proto::Kerberos::Crypto::Rc4Hmac

          # @!attribute vno
          #   @return [Fixnum] The authenticator version number
          attr_accessor :vno
          # @!attribute crealm
          #   @return [String] The realm in which the client is registered
          attr_accessor :crealm
          # @!attribute cname
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName] The name part of the client's principal
          #   identifier
          attr_accessor :cname
          # @!attribute checksum
          #   @return [Rex::Proto::Kerberos::Model::Checksum]
          attr_accessor :checksum
          # @!attribute cusec
          #   @return [Fixnum] The microsecond part of the client's timestamp
          attr_accessor :cusec
          # @!attribute ctime
          #   @return [Time] The current time of the client's host
          attr_accessor :ctime
          # @!attribute subkey
          #   @return [Rex::Proto::Kerberos::Model::EncryptionKey] the client's choice for an encryption
          #   key which is to be used to protect this specific application session
          attr_accessor :subkey

          def decode(input)
            raise ::RuntimeError, 'Authenticator decoding not supported'
          end

          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_vno], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_crealm], 1, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_cname], 2, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_checksum], 3, :CONTEXT_SPECIFIC) if checksum
            elems << OpenSSL::ASN1::ASN1Data.new([encode_cusec], 4, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_ctime], 5, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_subkey], 6, :CONTEXT_SPECIFIC) if subkey

            seq = OpenSSL::ASN1::Sequence.new(elems)
            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], AUTHENTICATOR, :APPLICATION)

            seq_asn1.to_der
          end

          # Encrypts the Rex::Proto::Kerberos::Model::Authenticator
          #
          # @param etype [Fixnum] the crypto schema to encrypt
          # @param key [String] the key to encrypt
          # @return [String] the encrypted result
          def encrypt(etype, key)
            data = self.encode

            res = ''
            case etype
            when KERB_ETYPE_RC4_HMAC
              res = encrypt_rc4_hmac(data, key, 7)
            else
              raise ::RuntimeError, 'EncryptedData schema is not supported'
            end

            res
          end


          private

          # Encodes the vno
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_vno
            bn = OpenSSL::BN.new(vno)
            int = OpenSSL::ASN1::Integer(bn)

            int
          end

          # Encodes the crealm
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_crealm
            OpenSSL::ASN1::GeneralString.new(crealm)
          end

          # Encodes the cname
          #
          # @return [String]
          def encode_cname
            cname.encode
          end

          # Encodes the checksum
          #
          # @return [String]
          def encode_checksum
            checksum.encode
          end

          # Encodes the cusec
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_cusec
            bn = OpenSSL::BN.new(cusec)
            int = OpenSSL::ASN1::Integer(bn)

            int
          end

          # Encodes the ctime field
          #
          # @return [OpenSSL::ASN1::GeneralizedTime]
          def encode_ctime
            OpenSSL::ASN1::GeneralizedTime.new(ctime)
          end

          def encode_subkey
            subkey.encode
          end
        end
      end
    end
  end
end