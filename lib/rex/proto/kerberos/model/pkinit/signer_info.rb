# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class SignerInfo < RASN1::Model
            sequence :signer_info,
                     content: [integer(:version),
                               model(:sid, IssuerAndSerialNumber),
                               model(:digest_algorithm, AlgorithmIdentifier),
                               set_of(:signed_attrs, Attribute, implicit: 0, optional: true),
                               model(:signature_algorithm, AlgorithmIdentifier),
                               octet_string(:signature),
#                               set_of(:unsigned_attrs, Attribute, implicit: 1, optional: true)
            ]
          end
        end
      end
    end
  end
end
