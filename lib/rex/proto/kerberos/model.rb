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
        ENC_KRB_CRED_PART = 29

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

        # From padata - https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml

        module PreAuthType
          PA_TGS_REQ = 1
          PA_ENC_TIMESTAMP = 2
          PA_PW_SALT = 3
          PA_ETYPE_INFO = 11
          PA_PK_AS_REQ = 16
          PA_PK_AS_REP = 17
          PA_ETYPE_INFO2 = 19
          PA_PAC_REQUEST = 128
          PA_SUPPORTED_ETYPES = 165
        end

        AD_IF_RELEVANT = 1
      end
    end
  end
end

