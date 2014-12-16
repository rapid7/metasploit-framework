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

        # Encryption Message Id's
        ENC_KDC_REQUEST_BODY = 10
        ENC_AS_RESPONSE = 8
        ENC_TGS_RESPONSE = 9

        KDC_OPTION_RESERVED        = 0
        KDC_OPTION_FORWARDABLE     = 1
        KDC_OPTION_FORWARDED       = 2
        KDC_OPTION_PROXIABLE       = 3
        KDC_OPTION_PROXY           = 4
        KDC_OPTION_ALLOW_POST_DATE = 5
        KDC_OPTION_POST_DATED      = 6
        KDC_OPTION_UNUSED_7        = 7
        KDC_OPTION_RENEWABLE       = 8
        KDC_OPTION_UNUSED_9        = 9
        KDC_OPTION_UNUSED_10       = 10
        KDC_OPTION_UNUSED_11       = 11
        KDC_OPTION_RENEWABLE_OK    = 27
        KDC_OPTION_ENC_TKT_IN_SKEY = 28
        KDC_OPTION_RENEW           = 30
        KDC_OPTION_VALIDATE        = 31

        # From Principal

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

        # From padata

        PA_TGS_REQ = 1
        PA_ENC_TIMESTAMP = 2
        PA_PW_SALT = 3
        PA_PAC_REQUEST = 128

        # From RFC-4757: The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows
        KERB_ETYPE_RC4_HMAC = 23
      end
    end
  end
end

require 'rex/proto/kerberos/model/element'
require 'rex/proto/kerberos/model/principal_name'
require 'rex/proto/kerberos/model/encrypted_data'
require 'rex/proto/kerberos/model/pre_auth_pac_request'
require 'rex/proto/kerberos/model/pre_auth_enc_time_stamp'
require 'rex/proto/kerberos/model/pre_auth_data'
require 'rex/proto/kerberos/model/kdc_request_body'
require 'rex/proto/kerberos/model/kdc_request'
require 'rex/proto/kerberos/model/krb_error'
require 'rex/proto/kerberos/model/ticket'
require 'rex/proto/kerberos/model/encryption_key'
require 'rex/proto/kerberos/model/last_request'
require 'rex/proto/kerberos/model/enc_kdc_response'
require 'rex/proto/kerberos/model/kdc_response'
