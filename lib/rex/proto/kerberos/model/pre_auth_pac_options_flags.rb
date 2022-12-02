# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # THe PA-PAC-OPTIONS KerberosFlags are represented as a bit string.
        # This module associates the human readable name, to the index the flag value is found at within the bit string.
        # https://www.rfc-editor.org/rfc/rfc4120.txt - KDCOptions      ::= KerberosFlags
        class PreAuthPacOptionsFlags < KerberosFlags
          # [MS-KILE] 2.2.10
          CLAIMS = 0
          BRANCH_AWARE = 1
          FORWARD_TO_FULL_DC = 2
          # [MS-SFU] 2.2.5
          RESOURCE_BASED_CONSTRAINED_DELEGATION = 3
        end

      end
    end
  end
end
