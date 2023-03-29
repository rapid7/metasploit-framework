# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a PA-Etype-Info2 structure,
        # which contains information about valid encryption types and salts 
        # that can be used to authenticate using Kerberos Pre-Authentication
        class PreAuthEtypeInfo2 < Element
          # @!attribute etype_info2_entries
          #   @return [Array<Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2Entry>] The list of all etype_info entries
          attr_accessor :etype_info2_entries

          # Decodes the Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2 from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode ETYPE-INFO2, invalid input'
            end

            self
          end

          def encode
            seq = encode_entries

            seq.to_der
          end

          private

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2 from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            self.etype_info2_entries = decode_etype_entries(input)
          end

          def decode_etype_entries(input)
            entries = []
            input.value.each do |val|
              entries.append(Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2Entry.decode(val))         
            end
            entries
          end

          # Encodes the name_string
          #
          # @return [OpenSSL::ASN1::Sequence]
          def encode_entries
            entries = []
            self.etype_info2_entries.each do |entry|
              entries << entry.encode
            end
            seq_string = OpenSSL::ASN1::Sequence.new(entries)

            seq_string
          end

        end
      end
    end
  end
end
