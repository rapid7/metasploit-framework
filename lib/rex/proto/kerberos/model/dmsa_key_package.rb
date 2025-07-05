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
            input.value.map { |key| EncryptionKey.decode(key) }
          end

          def encode_keys(keys)
            keys.map(&:encode)
          end

          def decode_time(input)
            KerberosTime.decode(input.value[0])
          end

          def encode_time(time)
            time.encode
          end
        end
      end
    end
  end
end