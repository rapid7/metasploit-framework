# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class KdcDhKeyInfo < RASN1::Model
            sequence :kdc_dh_key_info,
                     content: [bit_string(:subject_public_key, explicit: 0, constructed: true),
                               integer(:nonce, implicit: 1, constructed: true),
                               generalized_time(:dh_key_expiration, explicit: 2, constructed: true)
            ]
          end
        end
      end
    end
  end
end
