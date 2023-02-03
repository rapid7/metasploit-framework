# -*- coding: binary -*-
require 'rasn1'

module Rex
  module Proto
    module Kerberos
      module Model
        # Contains the models for PKINIT-related ASN1 structures
        # These use the RASN1 library to define the types
        module Pkinit
          class AlgorithmIdentifier < RASN1::Model
            sequence :algorithm_identifier,
                     content: [objectid(:algorithm),
                               any(:parameters, optional: true)
            ]
          end

          class Attribute < RASN1::Model
            sequence :attribute,
                     content: [objectid(:attribute_type),
                               set_of(:attribute_values, RASN1::Types::Any)
            ]
          end

          class AttributeTypeAndValue < RASN1::Model
            sequence :attribute_type_and_value,
                     content: [objectid(:attribute_type),
                               any(:attribute_value)
            ]
          end

          class Certificate
            # Rather than specifying the entire structure of a certificate, we pass this off
            # to OpenSSL, effectively providing an interface between RASN and OpenSSL.

            attr_accessor :options

            def initialize(options={})
              self.options = options
            end

            def to_der
              self.options[:openssl_certificate]&.to_der || ''
            end

            # RASN1 Glue method - Say if DER can be built (not default value, not optional without value, has a value)
            # @return [Boolean]
            # @since 0.12
            def can_build?
              !to_der.empty?
            end

            # RASN1 Glue method
            def primitive?
              false
            end

            # RASN1 Glue method
            def value
              options[:openssl_certificate]
            end

            def parse!(str, ber: false)
              self.options[:openssl_certificate] = OpenSSL::X509::Certificate.new(str)
              to_der.length
            end
          end

          class ContentInfo < RASN1::Model
            sequence :content_info,
                     content: [objectid(:content_type),
                               # In our case, expected to be SignedData
                               any(:signed_data)
            ]

            def signed_data
              if self[:content_type].value == '1.2.840.113549.1.7.2'
                SignedData.parse(self[:signed_data].value)
              end
            end
          end

          class DomainParameters < RASN1::Model
            sequence :domain_parameters,
                     content: [integer(:p),
                               integer(:g),
                               integer(:q),
                               integer(:j, optional: true),
                               #model(:validationParms, ValidationParms) # Not used, so not implemented
            ]
          end

          class EncapsulatedContentInfo < RASN1::Model
            sequence :encapsulated_content_info,
                     content: [objectid(:econtent_type),
                               octet_string(:econtent, explicit: 0, constructed: true, optional: true)
            ]

            def econtent
              if self[:econtent_type].value == '1.3.6.1.5.2.3.2'
                KdcDhKeyInfo.parse(self[:econtent].value)
              elsif self[:econtent_type].value == '1.3.6.1.5.2.3.1'
                AuthPack.parse(self[:econtent].value)
              end
            end
          end

          class Name
            # Rather than specifying the entire structure of a name, we pass this off
            # to OpenSSL, effectively providing an interface between RASN and OpenSSL.
            attr_accessor :value

            def initialize(options={})
            end

            def parse!(str, ber: false)
              self.value = OpenSSL::X509::Name.new(str)
              to_der.length
            end

            def to_der
              self.value.to_der
            end
          end

          class IssuerAndSerialNumber < RASN1::Model
            sequence :signer_identifier,
                     content: [model(:issuer, Name),
                               integer(:serial_number)
            ]
          end

          class KdcDhKeyInfo < RASN1::Model
            sequence :kdc_dh_key_info,
                     content: [bit_string(:subject_public_key, explicit: 0, constructed: true),
                               integer(:nonce, implicit: 1, constructed: true),
                               generalized_time(:dh_key_expiration, explicit: 2, constructed: true)
            ]
          end

          class PkAuthenticator < RASN1::Model
            sequence :pk_authenticator,
                     explicit: 0, constructed: true,
                     content: [integer(:cusec, constructed: true, explicit: 0),
                               generalized_time(:ctime, constructed: true, explicit: 1),
                               integer(:nonce, constructed: true, explicit: 2),
                               octet_string(:pa_checksum, constructed: true, explicit: 3, optional: true)
            ]
          end

          class SignerInfo < RASN1::Model
            sequence :signer_info,
                     content: [integer(:version),
                               model(:sid, IssuerAndSerialNumber),
                               model(:digest_algorithm, AlgorithmIdentifier),
                               set_of(:signed_attrs, Attribute, implicit: 0, optional: true),
                               model(:signature_algorithm, AlgorithmIdentifier),
                               octet_string(:signature),
            ]
          end

          class SignedData < RASN1::Model
            sequence :signed_data,
                     explicit: 0, constructed: true,
                     content: [integer(:version),
                               set_of(:digest_algorithms, AlgorithmIdentifier),
                               model(:encap_content_info, EncapsulatedContentInfo),
                               set_of(:certificates, Certificate, implicit: 0, optional: true),
                               # CRLs - not implemented
                               set_of(:signer_infos, SignerInfo)
            ]
          end

          class SubjectPublicKeyInfo < RASN1::Model
            sequence :subject_public_key_info,
                    explicit: 1, constructed: true, optional: true,
                     content: [model(:algorithm, AlgorithmIdentifier),
                               bit_string(:subject_public_key)
            ]
          end

          class AuthPack < RASN1::Model
            sequence :auth_pack,
                     content: [model(:pk_authenticator, PkAuthenticator),
                               model(:client_public_value, SubjectPublicKeyInfo),
                               octet_string(:client_dh_nonce, implicit: 3, constructed: true, optional: true)
            ]
          end
        end
      end
    end
  end
end

