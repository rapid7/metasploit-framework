# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # THe KdcOptions KerberosFlags are represented as a bit string.
        # This module associates the human readable name, to the index the flag value is found at within the bit string.
        # https://www.rfc-editor.org/rfc/rfc4120.txt - KDCOptions      ::= KerberosFlags
        class KdcOptionFlags < KerberosFlags
          RESERVED = 0
          FORWARDABLE = 1
          FORWARDED = 2
          PROXIABLE = 3
          PROXY = 4
          ALLOW_POST_DATE = 5
          POST_DATED = 6
          INVALID = 7
          RENEWABLE = 8
          INITIAL = 9
          PRE_AUTHENT = 10
          HW_AUTHNET = 11
          TRANSITED_POLICY_CHECKED = 12
          OK_AS_DELEGATE = 13
          CNAME_IN_ADDL_TKT = 14
          CANONICALIZE = 15
          RENEWABLE_OK = 27
          ENC_TKT_IN_SKEY = 28
          RENEW = 30
          VALIDATE = 31
        end
      end
    end
  end
end
