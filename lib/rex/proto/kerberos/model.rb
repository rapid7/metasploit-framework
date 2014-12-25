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

        # Kerberos error codes
        ERROR_CODES = {
          0 => ['KDC_ERR_NONE', 'No error'],
          1 => ['KDC_ERR_NAME_EXP', 'Client\'s entry in database has expired'],
          2 => ['KDC_ERR_SERVICE_EXP', 'Server\'s entry in database has expired'],
          3 => ['KDC_ERR_BAD_PVNO', 'Requested protocol version number not supported'],
          4 => ['KDC_ERR_C_OLD_MAST_KVNO', 'Client\'s key encrypted in old master key'],
          5 => ['KDC_ERR_S_OLD_MAST_KVNO', 'Server\'s key encrypted in old master key'],
          6 => ['KDC_ERR_C_PRINCIPAL_UNKNOWN', 'Client not found in Kerberos database'],
          7 => ['KDC_ERR_S_PRINCIPAL_UNKNOWN', 'Server not found in Kerberos database'],
          8 => ['KDC_ERR_PRINCIPAL_NOT_UNIQUE', 'Multiple principal entries in database'],
          9 => ['KDC_ERR_NULL_KEY', 'The client or server has a null key'],
          10 => ['KDC_ERR_CANNOT_POSTDATE', 'Ticket not eligible for postdating'],
          11 => ['KDC_ERR_NEVER_VALID', 'Requested start time is later than end time'],
          12 => ['KDC_ERR_POLICY', 'KDC policy rejects request'],
          13 => ['KDC_ERR_BADOPTION', 'KDC cannot accommodate requested option'],
          14 => ['KDC_ERR_ETYPE_NOSUPP', 'KDC has no support for encryption type'],
          15 => ['KDC_ERR_SUMTYPE_NOSUPP', 'KDC has no support for checksum type'],
          16 => ['KDC_ERR_PADATA_TYPE_NOSUPP', 'KDC has no support for padata type'],
          17 => ['KDC_ERR_TRTYPE_NOSUPP', 'KDC has no support for transited type'],
          18 => ['KDC_ERR_CLIENT_REVOKED', 'Clients credentials have been revoked'],
          19 => ['KDC_ERR_SERVICE_REVOKED', 'Credentials for server have been revoked'],
          20 => ['KDC_ERR_TGT_REVOKED', 'TGT has been revoked'],
          21 => ['KDC_ERR_CLIENT_NOTYET', 'Client not yet valid - try again later'],
          22 => ['KDC_ERR_SERVICE_NOTYET', 'Server not yet valid - try again later'],
          23 => ['KDC_ERR_KEY_EXPIRED', 'Password has expired - change password to reset'],
          24 => ['KDC_ERR_PREAUTH_FAILED', 'Pre-authentication information was invalid'],
          25 => ['KDC_ERR_PREAUTH_REQUIRED', 'Additional pre-authentication required'],
          31 => ['KRB_AP_ERR_BAD_INTEGRITY', 'Integrity check on decrypted field failed'],
          32 => ['KRB_AP_ERR_TKT_EXPIRED', 'Ticket expired'],
          33 => ['KRB_AP_ERR_TKT_NYV', 'Ticket not yet valid'],
          34 => ['KRB_AP_ERR_REPEAT', 'Request is a replay'],
          35 => ['KRB_AP_ERR_NOT_US', 'The ticket isn\'t for us'],
          36 => ['KRB_AP_ERR_BADMATCH', 'Ticket and authenticator don\'t match'],
          37 => ['KRB_AP_ERR_SKEW', 'Clock skew too great'],
          38 => ['KRB_AP_ERR_BADADDR', 'Incorrect net address'],
          39 => ['KRB_AP_ERR_BADVERSION', 'Protocol version mismatch'],
          40 => ['KRB_AP_ERR_MSG_TYPE', 'Invalid msg type'],
          41 => ['KRB_AP_ERR_MODIFIED', 'Message stream modified'],
          42 => ['KRB_AP_ERR_BADORDER', 'Message out of order'],
          44 => ['KRB_AP_ERR_BADKEYVER', 'Specified version of key is not available'],
          45 => ['KRB_AP_ERR_NOKEY', 'Service key not available'],
          46 => ['KRB_AP_ERR_MUT_FAIL', 'Mutual authentication failed'],
          47 => ['KRB_AP_ERR_BADDIRECTION', 'Incorrect message direction'],
          48 => ['KRB_AP_ERR_METHOD', 'Alternative authentication method required'],
          49 => ['KRB_AP_ERR_BADSEQ', 'Incorrect sequence number in message'],
          50 => ['KRB_AP_ERR_INAPP_CKSUM', 'Inappropriate type of checksum in message'],
          60 => ['KRB_ERR_GENERIC', 'Generic error'],
          61 => ['KRB_ERR_FIELD_TOOLONG', 'Field is too long for this implementation']
        }

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

        AD_IF_RELEVANT = 1
      end
    end
  end
end

require 'rex/proto/kerberos/model/element'
require 'rex/proto/kerberos/model/principal_name'
require 'rex/proto/kerberos/model/encrypted_data'
require 'rex/proto/kerberos/model/checksum'
require 'rex/proto/kerberos/model/pre_auth_pac_request'
require 'rex/proto/kerberos/model/pre_auth_enc_time_stamp'
require 'rex/proto/kerberos/model/pre_auth_data'
require 'rex/proto/kerberos/model/ap_req'
require 'rex/proto/kerberos/model/krb_error'
require 'rex/proto/kerberos/model/authorization_data'
require 'rex/proto/kerberos/model/encryption_key'
require 'rex/proto/kerberos/model/authenticator'
require 'rex/proto/kerberos/model/ticket'
require 'rex/proto/kerberos/model/last_request'
require 'rex/proto/kerberos/model/kdc_request_body'
require 'rex/proto/kerberos/model/kdc_request'
require 'rex/proto/kerberos/model/enc_kdc_response'
require 'rex/proto/kerberos/model/kdc_response'
