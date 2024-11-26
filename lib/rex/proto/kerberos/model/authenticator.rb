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
          # @!attribute enc_key_usage
          #   @return [Rex::Proto::Kerberos::Crypto::KeyUsage,Integer] The enc key usage number for this authenticator
          attr_accessor :enc_key_usage
          # @!attribute sequence_number
          #   @return [Integer] The initial sequence number to be used for future communications
          attr_accessor :sequence_number

          # Decodes the Rex::Proto::Kerberos::Model::Authenticator from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode Authenticator, invalid input'
            end

            self
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
            elems << OpenSSL::ASN1::ASN1Data.new([encode_sequence_number], 7, :CONTEXT_SPECIFIC) if sequence_number

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
            raise ::Rex::Proto::Kerberos::Model::Error::KerberosError, 'Missing enc_key_usage' unless enc_key_usage

            data = self.encode
            encryptor = Rex::Proto::Kerberos::Crypto::Encryption::from_etype(etype)
            encryptor.encrypt(data, key, enc_key_usage)
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

          # Encodes the sequence_number field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_sequence_number
            bn = OpenSSL::BN.new(sequence_number.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Decodes a Rex::Proto::Kerberos::Model::Authenticator from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::Authenticator
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 0
                self.vno = decode_vno(val)
              when 1
                self.crealm = decode_crealm(val)
              when 2
                self.cname = decode_cname(val)
              when 4
                self.cusec = decode_cusec(val)
              when 5
                self.ctime = decode_ctime(val)
              when 6
                self.subkey = decode_subkey(val)
              when 7
                self.sequence_number = decode_sequence_number(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Failed to decode AUTHENTICATOR SEQUENCE (#{val.tag})"
              end
            end
          end
          # Decodes the vno from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_vno(input)
            input.value[0].value.to_i
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

          # Decodes the crealm field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_crealm(input)
            input.value[0].value
          end

          # Decodes the cname field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::PrincipalName]
          def decode_cname(input)
            Rex::Proto::Kerberos::Model::PrincipalName.decode(input.value[0])
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
