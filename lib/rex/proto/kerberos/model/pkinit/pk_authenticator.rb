# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class PkAuthenticator < RASN1::Model
            sequence :pk_authenticator,
                     explicit: 0, constructed: true,
                     content: [integer(:cusec, constructed: true, explicit: 0),
                               generalized_time(:ctime, constructed: true, explicit: 1),
                               integer(:nonce, constructed: true, explicit: 2),
                               octet_string(:pa_checksum, constructed: true, explicit: 3, optional: true)
            ]
          end
        end
      end
    end
  end
end
