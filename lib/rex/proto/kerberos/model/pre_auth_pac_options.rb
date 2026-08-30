module Rex
  module Proto
    module Kerberos
      module Model
        # This class is a representation of a PA-PAC-OPTIONS, which specifies
        # explicitly requested options in the PAC as defined in
        # https://learn.microsoft.com/fr-fr/openspecs/windows_protocols/ms-kile/99721a01-c859-48d1-8310-ec1bab9b2838
        # and
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/aeecfd82-a5e4-474c-92ab-8df9022cf955
        class PreAuthPacOptions < Element

          # @!attribute flags
          #   @return [Integer] The PA-PAC-OPTIONS flags
          attr_accessor :flags

          # Decodes the Rex::Proto::Kerberos::Model::PreAuthPacOptions from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PreAuthPacOptions, invalid input'
            end

            self
          end

          # Encodes the Rex::Proto::Kerberos::Model::PreAuthPacOptions into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_flags], 0, :CONTEXT_SPECIFIC)

            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq.to_der
          end

          # Encodes the flags
          #
          # @return [OpenSSL::ASN1::BitString]
          def encode_flags
            OpenSSL::ASN1::BitString.new([flags.to_i].pack('N'))
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthPacOptions from an String
          #
          # @param input [String] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          rescue OpenSSL::ASN1::ASN1Error
            raise Rex::Proto::Kerberos::Model::Error::KerberosDecodingError
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthPacOptions from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            seq_values = input.value

            seq_values.each do |val|
              case val.tag
              when 0
                self.options = decode_flags(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PreAuthPacOptions SEQUENCE'
              end
            end
          end

          # Decodes the flags field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_flags(input)
            input.value[0].value.unpack('N')[0]
          end



        end
      end
    end
  end
end

