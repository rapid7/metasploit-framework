 # -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        VERSION = 5

        # Application Message Id's

        AS_REQ = 10
        AS_REP = 11
        TGS_REQ = 12
        TGS_REP = 13
        KRB_ERROR = 30
        TICKET = 1
        AUTHENTICATOR = 2
        AP_REQ = 14
        AP_REP = 15
        KRB_CRED = 22
        ENC_AP_REP_PART = 27
        ENC_KRB_CRED_PART = 29

        module OID
          DiffieHellman = '1.2.840.10046.2.1'
          SHA1 = '1.3.14.3.2.26'
          SHA256 = '2.16.840.1.101.3.4.2.1'
          ContentType = '1.2.840.113549.1.9.3'
          MessageDigest = '1.2.840.113549.1.9.4'
          RSAWithSHA1 = '1.2.840.113549.1.1.5'
          RSAWithSHA256 = '1.2.840.113549.1.1.11'
          PkinitAuthData = '1.3.6.1.5.2.3.1'
          SignedData = '1.2.840.113549.1.7.2'
        end

        # From Principal
        # https://datatracker.ietf.org/doc/html/rfc4120#section-6.2

        module NameType
          # Name type not known
          NT_UNKNOWN = 0
          # The name of the principal
          NT_PRINCIPAL = 1
          # Service and other unique instances
          NT_SRV_INST = 2
          # Service with host name and instance
          NT_SRV_HST = 3
          # Service with host as remaining component
          NT_SRV_XHST = 4
          # Unique ID
          NT_UID = 5
        end

        # See:
        # * https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#pre-authentication
        # * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ae60c948-fda8-45c2-b1d1-a71b484dd1f7

        module PreAuthType
          PA_TGS_REQ = 1
          PA_ENC_TIMESTAMP = 2
          PA_PW_SALT = 3
          PA_ETYPE_INFO = 11
          PA_PK_AS_REQ = 16
          PA_PK_AS_REP = 17
          PA_ETYPE_INFO2 = 19
          PA_PAC_REQUEST = 128
          PA_FOR_USER = 129
          PA_SUPPORTED_ETYPES = 165
          PA_PAC_OPTIONS = 167
          KERB_SUPERSEDED_BY_USER = 170
        end

        module AuthorizationDataType
          AD_IF_RELEVANT = 1
          KDC_ISSUED = 4
          AND_OR = 5
          MANDATORY_FOR_KDC = 8
          INITIAL_VERIFIED_CAS = 9
          OSF_DCE = 64
          SESAME = 65
        end
      end
    end
  end
end

