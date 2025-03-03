# -*- coding: binary -*-
require 'rasn1'.freeze
require 'rex/proto/crypto_asn1/types'

module Rex::Proto::CryptoAsn1
  class ObjectId < OpenSSL::ASN1::ObjectId
    attr_reader :label, :name
    def initialize(*args, label: nil, name: nil)
      @label = label
      @name = name
      super(*args)
    end

   def eql?(other)
      return false unless other.is_a?(self.class)
      return false unless other.value == value
      true
    end

    alias == eql?

    # Returns whether or not this OID is one of Microsoft's
    def microsoft?
      @value.start_with?('1.3.6.1.4.1.311.') || @value == '1.3.6.1.4.1.311'
    end
  end

  class OIDs
    # see: https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionenhancedkeyusage
    # see: https://www.pkisolutions.com/object-identifiers-oid-in-pki/
    OID_ANY_APPLICATION_POLICY = ObjectId.new('1.3.6.1.4.1.311.10.12.1', name: 'OID_ANY_APPLICATION_POLICY')
    OID_AUTO_ENROLL_CTL_USAGE = ObjectId.new('1.3.6.1.4.1.311.20.1', name: 'OID_AUTO_ENROLL_CTL_USAGE', label: 'CTL Usage')
    OID_DRM = ObjectId.new('1.3.6.1.4.1.311.10.5.1', name: 'OID_DRM', label: 'Digital Rights')
    OID_DS_EMAIL_REPLICATION = ObjectId.new('1.3.6.1.4.1.311.21.19', name: 'OID_DS_EMAIL_REPLICATION', label: 'Directory Service Email Replication')
    OID_EFS_RECOVERY = ObjectId.new('1.3.6.1.4.1.311.10.3.4.1', name: 'OID_EFS_RECOVERY', label: 'File Recovery')
    OID_EMBEDDED_NT_CRYPTO = ObjectId.new('1.3.6.1.4.1.311.10.3.8', name: 'OID_EMBEDDED_NT_CRYPTO', label: 'Embedded Windows System Component Verification')
    OID_ENROLLMENT_AGENT = ObjectId.new('1.3.6.1.4.1.311.20.2.1', name: 'OID_ENROLLMENT_AGENT', label: 'Certificate Request Agent')
    OID_IPSEC_KP_IKE_INTERMEDIATE = ObjectId.new('1.3.6.1.5.5.8.2.2', name: 'OID_IPSEC_KP_IKE_INTERMEDIATE', label: 'IP Security IKE Intermediate')
    OID_KP_CA_EXCHANGE = ObjectId.new('1.3.6.1.4.1.311.21.5', name: 'OID_KP_CA_EXCHANGE', label: 'Private Key Archival')
    OID_KP_CTL_USAGE_SIGNING = ObjectId.new('1.3.6.1.4.1.311.10.3.1', name: 'OID_KP_CTL_USAGE_SIGNING', label: 'Microsoft Trust List Signing')
    OID_KP_DOCUMENT_SIGNING = ObjectId.new('1.3.6.1.4.1.311.10.3.12', name: 'OID_KP_DOCUMENT_SIGNING', label: 'Document Signing')
    OID_KP_EFS = ObjectId.new('1.3.6.1.4.1.311.10.3.4', name: 'OID_KP_EFS', label: 'Encrypting File System')
    OID_KP_KEY_RECOVERY = ObjectId.new('1.3.6.1.4.1.311.10.3.11', name: 'OID_KP_KEY_RECOVERY', label: 'Key Recovery')
    OID_KP_KEY_RECOVERY_AGENT = ObjectId.new('1.3.6.1.4.1.311.21.6', name: 'OID_KP_KEY_RECOVERY_AGENT', label: 'Key Recovery Agent')
    OID_KP_LIFETIME_SIGNING = ObjectId.new('1.3.6.1.4.1.311.10.3.13', name: 'OID_KP_LIFETIME_SIGNING', label: 'Lifetime Signing')
    OID_KP_QUALIFIED_SUBORDINATION = ObjectId.new('1.3.6.1.4.1.311.10.3.10', name: 'OID_KP_QUALIFIED_SUBORDINATION', label: 'Qualified Subordination')
    OID_KP_SMARTCARD_LOGON = ObjectId.new('1.3.6.1.4.1.311.20.2.2', name: 'OID_KP_SMARTCARD_LOGON', label: 'Smart Card Logon')
    OID_KP_TIME_STAMP_SIGNING = ObjectId.new('1.3.6.1.4.1.311.10.3.2', name: 'OID_KP_TIME_STAMP_SIGNING', label: 'Microsoft Time Stamping')
    OID_LICENSE_SERVER = ObjectId.new('1.3.6.1.4.1.311.10.6.2', name: 'OID_LICENSE_SERVER', label: 'License Server Verification')
    OID_LICENSES = ObjectId.new('1.3.6.1.4.1.311.10.6.1', name: 'OID_LICENSES', label: 'Key Pack Licenses')
    OID_NT5_CRYPTO = ObjectId.new('1.3.6.1.4.1.311.10.3.7', name: 'OID_NT5_CRYPTO', label: 'OEM Windows System Component Verification')
    OID_OEM_WHQL_CRYPTO = ObjectId.new('1.3.6.1.4.1.311.10.3.7', name: 'OID_OEM_WHQL_CRYPTO', label: 'OEM Windows System Component Verification')
    OID_PKIX_KP_CLIENT_AUTH = ObjectId.new('1.3.6.1.5.5.7.3.2', name: 'OID_PKIX_KP_CLIENT_AUTH', label: 'Client Authentication')
    OID_PKIX_KP_CODE_SIGNING = ObjectId.new('1.3.6.1.5.5.7.3.3', name: 'OID_PKIX_KP_CODE_SIGNING', label: 'Code Signing')
    OID_PKIX_KP_EMAIL_PROTECTION = ObjectId.new('1.3.6.1.5.5.7.3.4', name: 'OID_PKIX_KP_EMAIL_PROTECTION', label: 'Secure Email')
    OID_PKIX_KP_IPSEC_END_SYSTEM = ObjectId.new('1.3.6.1.5.5.7.3.5', name: 'OID_PKIX_KP_IPSEC_END_SYSTEM', label: 'IP Security End System')
    OID_PKIX_KP_IPSEC_TUNNEL = ObjectId.new('1.3.6.1.5.5.7.3.6', name: 'OID_PKIX_KP_IPSEC_TUNNEL', label: 'IP Security Tunnel Termination')
    OID_PKIX_KP_IPSEC_USER = ObjectId.new('1.3.6.1.5.5.7.3.7', name: 'OID_PKIX_KP_IPSEC_USER', label: 'IP Security User')
    OID_PKIX_KP_OCSP_SIGNING = ObjectId.new('1.3.6.1.5.5.7.3.9', name: 'OID_PKIX_KP_OCSP_SIGNING', label: 'OCSP Signing')
    OID_PKIX_KP_SERVER_AUTH = ObjectId.new('1.3.6.1.5.5.7.3.1', name: 'OID_PKIX_KP_SERVER_AUTH', label: 'Server Authentication')
    OID_PKIX_KP_TIMESTAMP_SIGNING = ObjectId.new('1.3.6.1.5.5.7.3.8', name: 'OID_PKIX_KP_TIMESTAMP_SIGNING', label: 'Time Stamping')
    OID_ROOT_LIST_SIGNER = ObjectId.new('1.3.6.1.4.1.311.10.3.9', name: 'OID_ROOT_LIST_SIGNER', label: 'Root List Signer')
    OID_WHQL_CRYPTO = ObjectId.new('1.3.6.1.4.1.311.10.3.5', name: 'OID_WHQL_CRYPTO', label: 'Windows Hardware Driver Verification')

    OID_CMS_ENVELOPED_DATA = ObjectId.new('1.2.840.113549.1.7.3', name: 'OID_CMS_ENVELOPED_DATA', label: 'PKCS#7 CMS Enveloped Data')

    OID_DES_EDE3_CBC = ObjectId.new('1.2.840.113549.3.7', name: 'OID_DES_EDE_CBC', label: 'Triple DES encryption in CBC mode')
    OID_AES256_CBC = ObjectId.new('2.16.840.1.101.3.4.1.42', name: 'OID_AES256_CBC', label: 'AES256 in CBC mode')
    OID_RSA_ENCRYPTION = ObjectId.new('1.2.840.113549.1.1.1', name: 'OID_RSA_ENCRYPTION', label: 'RSA public key encryption')
    OID_RSAES_OAEP = ObjectId.new('1.2.840.113549.1.1.7', name: 'OID_RSAES_OAEP', label: 'RSA public key encryption with OAEP padding')

    def self.name(value)
      value = ObjectId.new(value) if value.is_a?(String)

      constants.select { |c| c.start_with?('OID_') }.find{ |c| const_get(c) == value }
    end

    def self.value(value)
      name = self.name(value)
      return nil unless name

      const_get(name)
    end
  end
end
