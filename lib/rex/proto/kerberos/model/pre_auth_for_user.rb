module Rex
  module Proto
    module Kerberos
      module Model
        # This class is a representation of a PA-FOR-USER, pre authenticated
        # data to identify the user on whose behalf a service requests a
        # service ticket, as defined in
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/aceb70de-40f0-4409-87fa-df00ca145f5a
        class PreAuthForUser < Element

          # @!attribute user_name
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName] The name
          #   part of the user's principal identifier
          attr_accessor :user_name
          # @!attribute user_realm
          #   @return [String] The realm part of the user's principal identifier
          attr_accessor :user_realm
          # @!attribute cksum
          #   @return [Rex::Proto::Kerberos::Model::Checksum] The checksum of
          #   user_name, user_realm, and auth_package.
          attr_accessor :cksum
          # @!attribute auth_package
          #   @return [String] The authentication mechanism used to
          #   authenticate the user.
          attr_accessor :auth_package

          # Decodes the Rex::Proto::Kerberos::Model::PreAuthForUser from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PreAuthForUser, invalid input'
            end

            self
          end

          # Encodes the Rex::Proto::Kerberos::Model::PreAuthForUser into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_user_name], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_user_realm], 1, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_cksum], 2, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_auth_package], 3, :CONTEXT_SPECIFIC)

            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq.to_der
          end

          # Encodes the user_name attribute
          #
          # @return [String]
          def encode_user_name
            user_name.encode
          end

          # Encodes the user_realm attribute
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_user_realm
            OpenSSL::ASN1::GeneralString.new(user_realm)
          end

          # Encodes the cksum attribute
          #
          # @return [String]
          def encode_cksum
            cksum.encode
          end

          # Encodes the auth_package attribute
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_auth_package
            OpenSSL::ASN1::GeneralString.new(auth_package)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthForUser from an String
          #
          # @param input [String] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          rescue OpenSSL::ASN1::ASN1Error
            raise Rex::Proto::Kerberos::Model::Error::KerberosDecodingError
          end

          # Decodes a Rex::Proto::Kerberos::Model::PreAuthForUser from an
          # OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            seq_values = input.value

            seq_values.each do |val|
              case val.tag
              when 0
                self.user_name = decode_user_name(val)
              when 1
                self.user_realm = decode_user_realm(val)
              when 2
                self.cksum = decode_cksum(val)
              when 3
                self.auth_package = decode_auth_package(val)
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode KdcRequestBody SEQUENCE'
              end
            end
          end

          # Decodes the user_name field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::PrincipalName]
          def decode_user_name(input)
            Rex::Proto::Kerberos::Model::PrincipalName.decode(input.value[0])
          end

          # Decodes the user_realm field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_user_realm(input)
            input.value[0].value
          end

          # Decodes the cksum field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Rex::Proto::Kerberos::Model::PrincipalName]
          def decode_cksum(input)
            Rex::Proto::Kerberos::Model::Checksum.decode(input.value[0])
          end

          # Decodes the auth_package field
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [String]
          def decode_auth_package(input)
            input.value[0].value
          end

        end
      end
    end
  end
end

