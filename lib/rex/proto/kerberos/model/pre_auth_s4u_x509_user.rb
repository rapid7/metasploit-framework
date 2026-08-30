# -*- coding: binary -*-

require 'openssl'

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of the PA-S4U-X509-USER structure
        # as defined in the Kerberos protocol.
        class PreAuthS4uX509User < Element
          # @!attribute user_id
          #   @return [Rex::Proto::Kerberos::Model::S4uUserId] The user ID
          attr_accessor :user_id
          # @!attribute checksum
          #   @return [Rex::Proto::Kerberos::Model::Checksum] The checksum
          attr_accessor :checksum

          def get_checksum(key, data)
            checksum_type = Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES256
            cksum_key_usage = Rex::Proto::Kerberos::Crypto::KeyUsage::PA_S4U_X509_USER
            checksummer = Rex::Proto::Kerberos::Crypto::Checksum::from_checksum_type(checksum_type)
            checksummer.checksum(key, cksum_key_usage, data)
          end

          # Initializes the PA-S4U-X509-USER structure
          #
          # @param key [String] The encryption key
          # @param impersonate [String] The impersonation principal name
          # @param impersonate_type [String] The impersonation principal name
          # @param realm [String] The realm
          # @param nonce [Integer] The nonce
          # @param e_type [Symbol] The encryption type
          def initialize(key, impersonate, impersonate_type, realm, nonce, e_type: Rex::Proto::Kerberos::Crypto::Encryption::AES256)
            self.user_id = Rex::Proto::Kerberos::Model::S4uUserId.new(impersonate, impersonate_type, realm, nonce)
            self.checksum = Rex::Proto::Kerberos::Model::Checksum.new(type: Rex::Proto::Kerberos::Crypto::Encryption::DES3_CBC_SHA1, checksum: get_checksum(key.value, user_id.encode))
          end

          # Encodes the PA-S4U-X509-USER structure into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([user_id.encode], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([checksum.encode], 1, :CONTEXT_SPECIFIC)

            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq.to_der
           end

          # Decodes the PA-S4U-X509-USER structure from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PA-S4U-X509-USER, invalid input'
            end

            self
          end

          # Decodes the PA-S4U-X509-USER structure from a String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)
            decode_asn1(asn1)
          end

          # Decodes the PA-S4U-X509-USER structure from an OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          def decode_asn1(input)
            seq_values = input.value

            seq_values.each do |val|
              case val.tag
              when 0
                self.user_id = S4uUserId.decode(val.value[0])
              when 1
                self.checksum = Checksum.new.decode(val.value[0])
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PA-S4U-X509-USER SEQUENCE'
              end
            end
          end
        end
      end
    end
  end
end
