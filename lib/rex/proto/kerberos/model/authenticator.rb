# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of an Authenticator, sent with a
        # ticket to the server to certify the client's knowledge of the encryption
        # key in the ticket.
        class Authenticator < Element
          # @!attribute vno
          #   @return [Integer] The authenticator version number
          attr_accessor :vno
          # @!attribute crealm
          #   @return [String] The realm in which the client is registered
          attr_accessor :crealm
          # @!attribute cname
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName] The name part of the client's principal
          #   identifier
          attr_accessor :cname
          # @!attribute checksum
          #   @return [Rex::Proto::Kerberos::Model::Checksum] The checksum of the application data that
          #   accompanies the KRB_AP_REQ.
          attr_accessor :checksum
          # @!attribute cusec
          #   @return [Integer] The microsecond part of the client's timestamp
          attr_accessor :cusec
          # @!attribute ctime
          #   @return [Time] The current time of the client's host
          attr_accessor :ctime
          # @!attribute subkey
          #   @return [Rex::Proto::Kerberos::Model::EncryptionKey] the client's choice for an encryption
          #   key which is to be used to protect this specific application session
          attr_accessor :subkey

          # Rex::Proto::Kerberos::Model::Authenticator decoding isn't supported
          #
          # @raise [NotImplementedError]
          def decode(input)
            raise ::NotImplementedError, 'Authenticator decoding not supported'
          end

          # Encodes the Rex::Proto::Kerberos::Model::Authenticator into an ASN.1 String
          #
          # @return [String]
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
          # @param etype [Integer] the crypto schema to encrypt
          # @param key [String] the key to encrypt
          # @return [String] the encrypted result
          # @raise [NotImplementedError] if the encryption schema isn't supported
          def encrypt(etype, key)
            data = self.encode

            res = ''
            case etype
            when RC4_HMAC
              res = encrypt_rc4_hmac(data, key, 7)
            else
              raise ::NotImplementedError, 'EncryptedData schema is not supported'
            end

            res
          end


          private

          # Encodes the vno field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_vno
            bn = OpenSSL::BN.new(vno.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the crealm field
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_crealm
            OpenSSL::ASN1::GeneralString.new(crealm)
          end

          # Encodes the cname field
          #
          # @return [String]
          def encode_cname
            cname.encode
          end

          # Encodes the checksum field
          #
          # @return [String]
          def encode_checksum
            checksum.encode
          end

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
        end
      end
    end
  end
end