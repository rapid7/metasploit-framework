# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of an EncAPRepPart, sent as the
        # encrypted part of an AP-REP message
        class EncApRepPart < Element
          # @!attribute ctime
          #   @return [Time] The current time of the client's host
          attr_accessor :ctime
          # @!attribute cusec
          #   @return [Integer] The microsecond part of the client's timestamp
          attr_accessor :cusec
          # @!attribute subkey
          #   @return [Rex::Proto::Kerberos::Model::EncryptionKey] the client's choice for an encryption
          #   key which is to be used to protect this specific application session
          attr_accessor :subkey
          # @!attribute sequence_number
          #   @return [Integer] The initial sequence number to be used for future communications
          attr_accessor :sequence_number

          # Decodes the Rex::Proto::Kerberos::Model::EncApRepPart from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode EncApRepPart, invalid input'
            end

            self
          end

          # Encodes the Rex::Proto::Kerberos::Model::EncApRepPart into an ASN.1 String
          #
          # @return [String]
          def encode
            raise ::NotImplementedError, 'EncApRepPart encoding not supported'
          end

          private

          # Decodes a Rex::Proto::Kerberos::Model::EncApRepPart from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::EncApRepPart
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value[0].value.each do |val|
              case val.tag
              when 0
                self.ctime = decode_ctime(val)
              when 1
                self.cusec = decode_cusec(val)
              when 2
                self.subkey = decode_subkey(val)
              when 3
                self.sequence_number = decode_sequence_number(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Failed to decode EncApRepPart SEQUENCE (#{val.tag})"
              end
            end
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
