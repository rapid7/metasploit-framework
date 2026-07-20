# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a Kerberos KERB-DMSA-KEY-PACKAGE
        # message as defined in [MS-KILE 2.2.13](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/79170b21-ad15-4a1b-99c4-84b3992d9e70).
        class DmsaKeyPackage < Element
          attr_accessor :current_keys
          attr_accessor :previous_keys
          attr_accessor :expiration_interval
          attr_accessor :fetch_interval

          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::Sequence
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode DmsaKeyPackage, invalid input'
            end

            self
          end

          def encode
            current_keys_asn1 = OpenSSL::ASN1::ASN1Data.new(encode_keys(current_keys), 0, :CONTEXT_SPECIFIC)
            previous_keys_asn1 = previous_keys ? OpenSSL::ASN1::ASN1Data.new(encode_keys(previous_keys), 1, :CONTEXT_SPECIFIC) : nil
            expiration_interval_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_time(expiration_interval)], 2, :CONTEXT_SPECIFIC)
            fetch_interval_asn1 = OpenSSL::ASN1::ASN1Data.new([encode_time(fetch_interval)], 4, :CONTEXT_SPECIFIC)

            seq = OpenSSL::ASN1::Sequence.new([current_keys_asn1, previous_keys_asn1, expiration_interval_asn1, fetch_interval_asn1].compact)

            seq.to_der
          end

          private

          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)
            decode_asn1(asn1)
          end

          def decode_asn1(input)
            seq_values = input.value
            self.current_keys = decode_keys(seq_values[0])
            self.previous_keys = seq_values[1] ? decode_keys(seq_values[1]) : nil
            self.expiration_interval = decode_time(seq_values[2])
            self.fetch_interval = decode_time(seq_values[3])
          end

          def decode_keys(input)
            elements = input.is_a?(OpenSSL::ASN1::ASN1Data) ? input.value : input
            elements.map do |element|
              if element.is_a?(Array)
                element.map { |sub_element| decode_type(sub_element) }
              else
                decode_type(element)
              end
            end
          end

          def decode_type(element)
            case element
            when OpenSSL::ASN1::Integer
              element.value.to_i
            when OpenSSL::ASN1::OctetString
              element.value
            when OpenSSL::ASN1::Sequence, OpenSSL::ASN1::ASN1Data
              element.value.map { |sub_element| decode_type(sub_element) }
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Unsupported element type: #{element.class}"
            end
          end

          def encode_keys(keys)
            keys.map(&:encode)
          end

          def decode_time(input)
            case input
            when OpenSSL::ASN1::ASN1Data
              generalized_time = input.value.first
              if generalized_time.is_a?(OpenSSL::ASN1::GeneralizedTime)
                Time.parse(generalized_time.value.to_s)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Unsupported time element type in ASN1Data: #{generalized_time.class}"
              end
            when OpenSSL::ASN1::GeneralizedTime
              Time.parse(input.value.to_s)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Unsupported time element type: #{input.class}"
            end
          end

          def encode_time(time)
            time.encode
          end
        end
      end
    end
  end
end