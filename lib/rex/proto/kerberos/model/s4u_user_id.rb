# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of the S4UUserID structure
        # as defined in the Kerberos protocol.
        class S4uUserId < Element
          # @!attribute nonce
          #   @return [Integer] The nonce in KDC-REQ-BODY
          attr_accessor :nonce
          # @!attribute cname
          #   @return [Rex::Proto::Kerberos::Model::PrincipalName, nil] The principal name (optional)
          attr_accessor :cname
          # @!attribute crealm
          #   @return [String] The realm
          attr_accessor :crealm
          # @!attribute subject_certificate
          #   @return [String, nil] The subject certificate (optional)
          attr_accessor :subject_certificate
          # @!attribute options
          #   @return [String, nil] The options (optional)
          attr_accessor :options

          ##
          #     //S4UUserID::= SEQUENCE {
          #     //    nonce[0] UInt32, --the nonce in KDC - REQ - BODY
          #     //    cname[1] PrincipalName OPTIONAL,
          #     //    --Certificate mapping hints
          #     //    crealm[2] Realm,
          #     //    subject-certificate[3] OCTET STRING OPTIONAL,
          #     //    options[4] BIT STRING OPTIONAL,
          #     //    ...
          #     //}


          def initialize(name, impersonate_type, realm, nonce)
            self.nonce = nonce
            # Set cname name_type based on dMSA flag
            self.cname = Rex::Proto::Kerberos::Model::PrincipalName.new(
              name_type: impersonate_type == 'dmsa' ? NameType::NT_PRINCIPAL : NameType::NT_ENTERPRISE,
              name_string: [name]
            )
            self.crealm = realm

            # Default options
            self.options = impersonate_type == 'dmsa' ? ::Rex::Proto::Kerberos::Model::PaS4uX509UserOptions::UNCONDITIONAL_DELEGATION | ::Rex::Proto::Kerberos::Model::PaS4uX509UserOptions::SIGN_REPLY : ::Rex::Proto::Kerberos::Model::PaS4uX509UserOptions::SIGN_REPLY
          end

          # Decodes the S4UUserID from an input
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
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode S4UUserID, invalid input'
            end

            self
          end

          # Encodes the S4UUserID into an ASN.1 String
          #
          # @return [String]
          def encode
            elems = []
            elems << OpenSSL::ASN1::ASN1Data.new([encode_nonce], 0, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_cname], 1, :CONTEXT_SPECIFIC) if cname
            elems << OpenSSL::ASN1::ASN1Data.new([encode_crealm], 2, :CONTEXT_SPECIFIC)
            elems << OpenSSL::ASN1::ASN1Data.new([encode_subject_certificate], 3, :CONTEXT_SPECIFIC) if subject_certificate
            # Convert options to a byte array
            options_bytes = [self.options].pack('N') # Pack as a big-endian unsigned 32-bit integer
            elems << OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString.new(options_bytes)], 4, :CONTEXT_SPECIFIC)


            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq.to_der
          end

          private

          # Encodes the nonce attribute
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_nonce
            OpenSSL::ASN1::Integer.new(nonce)
          end

          # Encodes the cname attribute
          #
          # @return [String]
          def encode_cname
            cname.encode
          end

          # Encodes the crealm attribute
          #
          # @return [OpenSSL::ASN1::GeneralString]
          def encode_crealm
            OpenSSL::ASN1::GeneralString.new(crealm)
          end

          # Encodes the subject_certificate attribute
          #
          # @return [OpenSSL::ASN1::OctetString]
          def encode_subject_certificate
            OpenSSL::ASN1::OctetString.new(subject_certificate)
          end

          # Encodes the options attribute
          #
          # @return [OpenSSL::ASN1::BitString]
          def encode_options
            OpenSSL::ASN1::BitString.new(options)
          end

          # Decodes the S4UUserID from a String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes the S4UUserID from an OpenSSL::ASN1::Sequence
          #
          # @param input [OpenSSL::ASN1::Sequence] the input to decode from
          def decode_asn1(input)
            seq_values = input.value

            seq_values.each do |val|
              case val.tag
              when 0
                self.nonce = val.value[0].value.to_i
              when 1
                self.cname = Rex::Proto::Kerberos::Model::PrincipalName.decode(val.value[0])
              when 2
                self.crealm = val.value[0].value
              when 3
                self.subject_certificate = val.value[0].value
              when 4
                self.options = val.value[0].value
              else
                raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode S4UUserID SEQUENCE'
              end
            end
          end
        end
      end
    end
  end
end