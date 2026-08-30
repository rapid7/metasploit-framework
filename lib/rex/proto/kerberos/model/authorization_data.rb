# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos AuthorizationData data
        # definition.
        class AuthorizationData < Element
          # @!attribute elements
          #   @return [Array<Hash{Symbol => Integer, String)}>] The type of the authorization data
          #   @option [Integer] :type
          #   @option [String] :data
          attr_accessor :elements

          # Decodes the Rex::Proto::Kerberos::Model::AuthorizationData from an input
          #
          # @param input [String, OpenSSL::ASN1::Sequence] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::ASN1Data
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode AuthorizationData, invalid input'
            end

            self
          end

          # Encodes a Rex::Proto::Kerberos::Model::AuthorizationData into an ASN.1 String
          #
          # @return [String]
          def encode
            seqs = []
            elements.each do |elem|
              elems = []
              type_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_type(elem[:type])], 0, :CONTEXT_SPECIFIC)
              elems << type_asn1
              data_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_data(elem[:data])], 1, :CONTEXT_SPECIFIC)
              elems << data_asn1
              seqs << OpenSSL::ASN1::Sequence.new(elems)
            end

            seq = OpenSSL::ASN1::Sequence.new(seqs)

            seq.to_der
          end

          # Decodes a Rex::Proto::Kerberos::Model::AuthorizationData from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::AuthorizationData
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          #
          #    TransitedEncoding       ::= SEQUENCE {
          #            ad-type         [0] Int32 -- must be registered --,
          #            ad-data         [1] OCTET STRING
          #    }
          def decode_asn1(input)
            self.elements = []
            input.each do |elem|
              element = {}
              elem.value.each do |val|
                case val.tag
                when 0  # ad-type         [0] Int32
                  element[:type] = decode_type(val)
                when 1  # ad-data        [1] OCTET STRING
                  element[:data] = decode_data(val)
                else
                  raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode AuthorizationData SEQUENCE'
                end
              end
              self.elements << element
            end
          end

          # Encrypts the Rex::Proto::Kerberos::Model::AuthorizationData
          #
          # @param etype [Integer] the crypto schema to encrypt
          # @param key [String] the key to encrypt
          # @return [String] the encrypted result
          # @raise [NotImplementedError] if encryption schema isn't supported
          def encrypt(etype, key)
            data = self.encode

            encryptor = Rex::Proto::Kerberos::Crypto::Encryption::from_etype(etype)
            encryptor.encrypt(data, key, 5)
          end


          private

          # Decodes the type from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_type(input)
            input.value[0].value.to_i
          end

          # Encodes the type
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_type(type)
            bn = OpenSSL::BN.new(type.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Decodes the value from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_data(input)
            input.value[0].value
          end

          # Encodes the data
          #
          # @return [OpenSSL::ASN1::OctetString]
          def encode_data(data)
            OpenSSL::ASN1::OctetString.new(data)
          end
        end
      end
    end
  end
end
