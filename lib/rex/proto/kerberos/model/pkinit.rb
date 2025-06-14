# -*- coding: binary -*-
require 'rasn1'

module Rex
  module Proto
    module Kerberos
      module Model
        # Contains the models for PKINIT-related ASN1 structures
        # These use the RASN1 library to define the types
        module Pkinit
          class DomainParameters < RASN1::Model
            sequence :domain_parameters,
                     content: [integer(:p),
                               integer(:g),
                               integer(:q),
                               integer(:j, optional: true),
                               #model(:validationParms, ValidationParms) # Not used, so not implemented
            ]
          end

          class KdcDhKeyInfo < RASN1::Model
            sequence :kdc_dh_key_info,
                     content: [bit_string(:subject_public_key, explicit: 0, constructed: true),
                               integer(:nonce, implicit: 1, constructed: true),
                               generalized_time(:dh_key_expiration, explicit: 2, constructed: true)
            ]
          end

          class PkAuthenticator < RASN1::Model
            sequence :pk_authenticator,
                     explicit: 0, constructed: true,
                     content: [integer(:cusec, constructed: true, explicit: 0),
                               generalized_time(:ctime, constructed: true, explicit: 1),
                               integer(:nonce, constructed: true, explicit: 2),
                               octet_string(:pa_checksum, constructed: true, explicit: 3, optional: true)
            ]
          end

          class AuthPack < RASN1::Model
            sequence :auth_pack,
                     content: [model(:pk_authenticator, PkAuthenticator),
                               model(:client_public_value, Rex::Proto::CryptoAsn1::X509::SubjectPublicKeyInfo),
                               octet_string(:client_dh_nonce, implicit: 3, constructed: true, optional: true)
            ]
          end
        end
      end
    end
  end
end

