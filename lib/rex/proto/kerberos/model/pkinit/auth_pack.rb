# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class AuthPack < RASN1::Model
            sequence :auth_pack,
                     content: [model(:pk_authenticator, PkAuthenticator),
                               model(:client_public_value, SubjectPublicKeyInfo),
#                               sequence_of(:supported_cms_types, AlgorithmIdentifier, implicit: 2, optional: true),
                               octet_string(:client_dh_nonce, implicit: 3, constructed: true, optional: true)
  
            ]
          end
        end
      end
    end
  end
end
