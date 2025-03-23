module Rex::Proto::CryptoAsn1::Cms
  class Attribute < RASN1::Model
    sequence :attribute,
             content: [objectid(:attribute_type),
                       set_of(:attribute_values, RASN1::Types::Any)
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

  class AlgorithmIdentifier < RASN1::Model
    sequence :algorithm_identifier,
             content: [objectid(:algorithm),
                       any(:parameters, optional: true)
    ]
  end

  class KeyDerivationAlgorithmIdentifier < AlgorithmIdentifier
  end

  class KeyEncryptionAlgorithmIdentifier < AlgorithmIdentifier
  end

  class ContentEncryptionAlgorithmIdentifier < AlgorithmIdentifier
  end

  class OriginatorInfo < RASN1::Model
    sequence :originator_info,
             content: [set_of(:certs, Certificate, implicit: 0, optional: true),
                       # CRLs - not implemented
                       ]
  end

  class ContentType < RASN1::Types::ObjectId
  end

  class EncryptedContent < RASN1::Types::OctetString
  end

  class EncryptedContentInfo < RASN1::Model
    sequence :encrypted_content_info,
             content: [model(:content_type, ContentType),
                       model(:content_encryption_algorithm, ContentEncryptionAlgorithmIdentifier),
                       wrapper(model(:encrypted_content, EncryptedContent), implicit: 0, optional: true)
                       ]
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

  class CmsVersion < RASN1::Types::Integer
  end

  class SubjectKeyIdentifier < RASN1::Types::OctetString
  end

  class UserKeyingMaterial < RASN1::Types::OctetString
  end

  class RecipientIdentifier < RASN1::Model
    choice :recipient_identifier,
           content: [model(:issuer_and_serial_number, IssuerAndSerialNumber),
                     wrapper(model(:subject_key_identifier, SubjectKeyIdentifier), implicit: 0)]
  end

  class EncryptedKey < RASN1::Types::OctetString
  end

  class OtherKeyAttribute < RASN1::Model
    sequence :other_key_attribute,
             content: [objectid(:key_attr_id),
                       any(:key_attr, optional: true)
                      ]
  end

  class RecipientKeyIdentifier < RASN1::Model
    sequence :recipient_key_identifier,
             content: [model(:subject_key_identifier, SubjectKeyIdentifier),
                       generalized_time(:date, optional: true),
                       wrapper(model(:other, OtherKeyAttribute), optional: true)
                      ]

  end

  class KeyAgreeRecipientIdentifier < RASN1::Model
    choice :key_agree_recipient_identifier,
           content: [model(:issuer_and_serial_number, IssuerAndSerialNumber),
                     wrapper(model(:r_key_id, RecipientKeyIdentifier), implicit: 0)]
  end

  class RecipientEncryptedKey < RASN1::Model
    sequence :recipient_encrypted_key,
             content: [model(:rid, KeyAgreeRecipientIdentifier),
                       model(:encrypted_key, EncryptedKey)]
  end

  class KEKIdentifier < RASN1::Model
    sequence :kek_identifier,
             content: [octet_string(:key_identifier),
                       generalized_time(:date, optional: true),
                       wrapper(model(:other, OtherKeyAttribute), optional: true)]
  end

  class KeyTransRecipientInfo < RASN1::Model
    sequence :key_trans_recipient_info,
             content: [model(:cms_version, CmsVersion),
                       model(:rid, RecipientIdentifier),
                       model(:key_encryption_algorithm, KeyEncryptionAlgorithmIdentifier),
                       model(:encrypted_key, EncryptedKey)
                      ]
  end

  class OriginatorPublicKey < RASN1::Model
    sequence :originator_public_key,
             content: [model(:algorithm, AlgorithmIdentifier),
                       bit_string(:public_key)]
  end

  class OriginatorIdentifierOrKey < RASN1::Model
    choice :originator_identifier_or_key,
           content: [model(:issuer_and_serial_number, IssuerAndSerialNumber),
                     model(:subject_key_identifier, SubjectKeyIdentifier),
                     model(:originator_public_key, OriginatorPublicKey)
                    ]
  end

  class KeyAgreeRecipientInfo < RASN1::Model
    sequence :key_agree_recipient_info,
             content: [model(:cms_version, CmsVersion),
                       wrapper(model(:originator, OriginatorIdentifierOrKey), explicit: 0),
                       wrapper(model(:ukm, UserKeyingMaterial), explicit: 1, optional: true),
                       model(:key_encryption_algorithm, KeyEncryptionAlgorithmIdentifier),
                       sequence_of(:recipient_encrypted_keys, RecipientEncryptedKey)
                      ]
  end

  class KEKRecipientInfo < RASN1::Model
    sequence :kek_recipient_info,
             content: [model(:cms_version, CmsVersion),
                       model(:kekid, KEKIdentifier),
                       model(:key_encryption_algorithm, KeyEncryptionAlgorithmIdentifier),
                       model(:encrypted_key, EncryptedKey)
                      ]
  end

  class PasswordRecipientInfo < RASN1::Model
    sequence :password_recipient_info,
             content: [model(:cms_version, CmsVersion),
                       wrapper(model(:key_derivation_algorithm, KeyDerivationAlgorithmIdentifier), explicit: 0, optional: true),
                       model(:key_encryption_algorithm, KeyEncryptionAlgorithmIdentifier),
                       model(:encrypted_key, EncryptedKey)
                      ]
  end

  class OtherRecipientInfo < RASN1::Model
    sequence :other_recipient_info,
             content: [objectid(:ore_type),
                       any(:ory_value)
                      ]
  end

  class RecipientInfo < RASN1::Model
    choice :recipient_info,
           content: [model(:ktri, KeyTransRecipientInfo),
                     wrapper(model(:kari, KeyAgreeRecipientInfo), implicit: 1),
                     wrapper(model(:kekri, KEKRecipientInfo), implicit: 2),
                     wrapper(model(:pwri, PasswordRecipientInfo), implicit: 3),
                     wrapper(model(:ori, OtherRecipientInfo), implicit: 4)]
  end

  class EnvelopedData < RASN1::Model
    sequence :enveloped_data,
             explicit: 0, constructed: true,
             content: [model(:cms_version, CmsVersion),
                       wrapper(model(:originator_info, OriginatorInfo), implict: 0, optional: true),
                       set_of(:recipient_infos, RecipientInfo),
                       model(:encrypted_content_info, EncryptedContentInfo),
                       set_of(:unprotected_attrs, Attribute, implicit: 1, optional: true),
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

  class EncapsulatedContentInfo < RASN1::Model
    sequence :encapsulated_content_info,
             content: [objectid(:econtent_type),
                       octet_string(:econtent, explicit: 0, constructed: true, optional: true)
    ]

    def econtent
      if self[:econtent_type].value == Rex::Proto::CryptoAsn1::OIDs::OID_DIFFIE_HELLMAN_KEYDATA.value
        Rex::Proto::Kerberos::Model::Pkinit::KdcDhKeyInfo.parse(self[:econtent].value)
      elsif self[:econtent_type].value == Rex::Proto::Kerberos::Model::OID::PkinitAuthData
        Rex::Proto::Kerberos::Model::Pkinit::AuthPack.parse(self[:econtent].value)
      end
    end
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

  class ContentInfo < RASN1::Model
    sequence :content_info,
             content: [model(:content_type, ContentType),
                       any(:data)
    ]

    def enveloped_data
      if self[:content_type].value == Rex::Proto::CryptoAsn1::OIDs::OID_CMS_ENVELOPED_DATA.value
        EnvelopedData.parse(self[:data].value)
      end
    end

    def signed_data
      if self[:content_type].value == Rex::Proto::CryptoAsn1::OIDs::OID_CMS_SIGNED_DATA.value
        SignedData.parse(self[:data].value)
      end
    end
  end
end