# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # The TicketFlags KerberosFlags are represented as a bit string.
        # This module associates the human readable name, to the index the flag value is found at within the bit string.
        # https://www.rfc-editor.org/rfc/rfc4120.txt
        #
        #    TicketFlags     ::= KerberosFlags
        #            -- reserved(0),
        #            -- forwardable(1),
        #            -- forwarded(2),
        #            -- proxiable(3),
        #            -- proxy(4),
        #            -- may-postdate(5),
        #            -- postdated(6),
        #            -- invalid(7),
        #            -- renewable(8),
        #            -- initial(9),
        #            -- pre-authent(10),
        #            -- hw-authent(11),
        #    -- the following are new since 1510
        #            -- transited-policy-checked(12),
        #            -- ok-as-delegate(13)
        #
        module TicketFlag
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
        end
      end
    end
  end
end
